/*
Castle Security System
Copyright (c) 2025 Fibb
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
The Castle Security System, including its name and concept, is the intellectual
property of Fibb. Use of the name "Castle Security System"
for commercial purposes or rebranding requires prior written permission from the owner.
*/

#include "castle_security.h"
// --- Standard C Library Includes for Implementation ---
#include <stdio.h>     // For printf, fprintf
#include <stdlib.h>    // For malloc, free
#include <string.h>    // For memset, strcpy, strcmp, strncpy
#include <errno.h>     // For errno
#include <unistd.h>    // For close (epoll), sleep
#include <sys/epoll.h> // For epoll_create, epoll_ctl, epoll_event (used by firewall_t)
#include <time.h>      // For time(NULL)
#include <arpa/inet.h> // For inet_pton (for IP validation)
#include <ctype.h>     // For isdigit (for port validation)

// --- Global Singleton Instance ---
// Defined here, declared extern in the header
static castle_security_system_t s_security_system_instance;
castle_security_system_t* g_security_system = &s_security_system_instance;

// Fairshare Warden global instance (if it's meant to be a separate global)
fairshare_warden_t Fairshare_Warden; // Defined here, declared extern in the header

// --- Helper Functions (Internal to this file) ---

// Event processing thread function
static void* event_processing_thread_func(void* arg) {
    castle_security_system_t* sys = (castle_security_system_t*)arg;
    if (!sys) return NULL;

    printf("[Event Thread] Event processing thread started.\n");
    while (atomic_load(&sys->event_stream.processing_active)) {
        pthread_mutex_lock(&sys->event_stream.queue_lock);
        // Wait for new events or until shutdown is requested
        while (sys->event_stream.head == NULL && atomic_load(&sys->event_stream.processing_active)) {
            pthread_cond_wait(&sys->event_stream.queue_cond, &sys->event_stream.queue_lock);
        }

        if (!atomic_load(&sys->event_stream.processing_active)) {
            pthread_mutex_unlock(&sys->event_stream.queue_lock);
            break; // Exit loop if shutdown requested
        }

        event_queue_node_t* node = sys->event_stream.head;
        sys->event_stream.head = sys->event_stream.head->next;
        if (sys->event_stream.head == NULL) {
            sys->event_stream.tail = NULL;
        }
        pthread_mutex_unlock(&sys->event_stream.queue_lock);

        // Process the event (e.g., log, update GUI)
        printf("[Event Thread] Processing event type %d: %s\n", node->entry.event_type, node->entry.details);
        on_security_event_received_gui_callback(&node->entry); // Update GUI
        free(node); // Free the queue node
    }
    printf("[Event Thread] Event processing thread stopped.\n");
    return NULL;
}

// --- NEW FEATURE: Automatic Memory Release for event_stream_t ---
void event_stream_cleanup(event_stream_t* stream) {
    if (!stream) return;

    // Stop the processing thread first
    atomic_store(&stream->processing_active, false);
    pthread_mutex_lock(&stream->queue_lock);
    pthread_cond_signal(&stream->queue_cond); // Wake up thread to check flag
    pthread_mutex_unlock(&stream->queue_lock);
    if (stream->processing_thread) {
        pthread_join(stream->processing_thread, NULL);
    }

    // Free remaining queue nodes
    event_queue_node_t* current = stream->head;
    while (current) {
        event_queue_node_t* next = current->next;
        free(current);
        current = next;
    }
    stream->head = NULL;
    stream->tail = NULL;

    // Free historical log entries
    if (stream->entries) {
        free(stream->entries);
        stream->entries = NULL;
    }

    // Destroy mutexes and condition variable
    pthread_mutex_destroy(&stream->lock);
    pthread_mutex_destroy(&stream->queue_lock);
    pthread_cond_destroy(&stream->queue_cond);

    printf("Event stream cleaned up.\n");
}

// --- Memory Pool Implementations ---
security_result_t memory_pool_init(memory_pool_t* pool, size_t block_size, size_t capacity) {
    if (!pool || block_size == 0 || capacity == 0) {
        fprintf(stderr, "Error: Invalid arguments for memory_pool_init.\n");
        return SECURITY_ERROR_INVALID_ARGS;
    }

    pool->buffer = malloc(block_size * capacity);
    if (!pool->buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for pool: %s\n", strerror(errno));
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }

    pool->block_size = block_size;
    pool->capacity = capacity;
    pool->used = 0;
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        fprintf(stderr, "Error: Failed to initialize memory pool mutex.\n");
        free(pool->buffer);
        pool->buffer = NULL;
        return SECURITY_ERROR_GENERIC_FAILURE;
    }

    printf("Memory pool initialized: block_size=%zu, capacity=%zu\n", block_size, capacity);
    return SECURITY_SUCCESS;
}

void memory_pool_destroy(memory_pool_t* pool) {
    if (pool) {
        if (pool->buffer) {
            free(pool->buffer);
            pool->buffer = NULL;
        }
        pthread_mutex_destroy(&pool->lock);
        printf("Memory pool destroyed.\n");
    }
}

// --- Security List Implementations ---
static security_result_t security_list_init(security_list_t* list, size_t initial_capacity) {
    if (!list || initial_capacity == 0) {
        return SECURITY_ERROR_INVALID_ARGS;
    }
    list->entries = (security_entry_t*)malloc(initial_capacity * sizeof(security_entry_t));
    if (!list->entries) {
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }
    list->capacity = initial_capacity;
    list->count = 0;
    atomic_store(&list->atomic_count, 0);
    if (pthread_mutex_init(&list->lock, NULL) != 0) {
        free(list->entries);
        list->entries = NULL;
        return SECURITY_ERROR_GENERIC_FAILURE;
    }
    return SECURITY_SUCCESS;
}

// --- NEW FEATURE: Automatic Memory Release for security_list_t ---
void security_list_cleanup(security_list_t* list) {
    if (list) {
        if (list->entries) {
            free(list->entries);
            list->entries = NULL;
        }
        pthread_mutex_destroy(&list->lock);
        list->capacity = 0;
        list->count = 0;
        atomic_store(&list->atomic_count, 0);
        printf("Security list cleaned up.\n");
    }
}

static security_result_t security_list_add(security_list_t* list, const char* rule, security_rule_type_t type, const char* description) {
    if (!list || !rule || !description) return SECURITY_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&list->lock);
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * SECURITY_DYNAMIC_GROWTH_FACTOR;
        security_entry_t* new_entries = (security_entry_t*)realloc(list->entries, new_capacity * sizeof(security_entry_t));
        if (!new_entries) {
            pthread_mutex_unlock(&list->lock);
            return SECURITY_ERROR_OUT_OF_MEMORY;
        }
        list->entries = new_entries;
        list->capacity = new_capacity;
    }

    security_entry_t* entry = &list->entries[list->count];
    // In a real system, 'rule' would be hashed to 'entry->hash'
    // --- IMPROVEMENT: Buffer Overflow Mitigation for fixed-length strings ---
    // Using strncpy with size checks to prevent buffer overflows.
    // Note: This still truncates long strings. For full flexibility, dynamic allocation is preferred.
    strncpy(entry->hash, rule, SECURITY_HASH_SIZE - 1);
    entry->hash[SECURITY_HASH_SIZE - 1] = '\0'; // Ensure null termination
    entry->timestamp = time(NULL);
    entry->flags = type; // Using flags to store rule type for simplicity
    strncpy(entry->description, description, SECURITY_MAX_RULE_LENGTH - 1);
    entry->description[SECURITY_MAX_RULE_LENGTH - 1] = '\0';

    list->count++;
    atomic_store(&list->atomic_count, list->count);
    pthread_mutex_unlock(&list->lock);
    printf("Added rule to list (type %d): %s - %s\n", type, rule, description);
    return SECURITY_SUCCESS;
}

static bool security_list_check(security_list_t* list, const char* rule, security_rule_type_t type) { // Removed redundant first arg
    if (!list || !rule) return false;

    pthread_mutex_lock(&list->lock); // Lock the target list directly
    bool found = false;
    // In a real system, 'rule' would be hashed and compared with entry->hash
    for (size_t i = 0; i < list->count; ++i) {
        if (list->entries[i].flags == type && strcmp(list->entries[i].hash, rule) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&list->lock);
    return found;
}

// --- Quantum Shield Operations ---
static security_result_t quantum_initialize_quantum_defense(quantum_context_t* qctx) {
    printf("Quantum Shield: Initializing quantum defense.\n");
    if (pthread_rwlock_init(&qctx->key_lock, NULL) != 0) return SECURITY_ERROR_GENERIC_FAILURE;
    // In a real scenario, OQS_KEM_new and OQS_SIG_new would be called
    // For this dummy implementation, we just set them to NULL.
    qctx->kem = NULL; // OQS_KEM_new(OQS_KEM_alg_kyber768);
    qctx->sig = NULL; // OQS_SIG_new(OQS_SIG_alg_dilithium3);
    if (qctx->kem == NULL || qctx->sig == NULL) {
        fprintf(stderr, "Quantum Shield: Failed to initialize OQS algorithms (dummy init, actual OQS calls commented out).\n");
        // return SECURITY_ERROR_QUANTUM_FAILURE; // Uncomment for real error
    }
    qctx->public_key = NULL;
    qctx->secret_key = NULL;
    qctx->public_key_len = 0;
    qctx->secret_key_len = 0;
    return SECURITY_SUCCESS;
}

static security_result_t quantum_generate_keys(quantum_context_t* qctx) {
    printf("Quantum Shield: Generating quantum keys.\n");
    if (!qctx) return SECURITY_ERROR_INVALID_ARGS;
    // if (!qctx->kem || !qctx->sig) return SECURITY_ERROR_QUANTUM_FAILURE; // Uncomment for real error

    pthread_rwlock_wrlock(&qctx->key_lock);
    // Free existing keys if any
    if (qctx->public_key) free(qctx->public_key);
    if (qctx->secret_key) free(qctx->secret_key);

    // In a real scenario, OQS_KEM_keypair and OQS_SIG_keypair would be called
    qctx->public_key_len = 32; // Example length
    qctx->secret_key_len = 64; // Example length
    qctx->public_key = (uint8_t*)malloc(qctx->public_key_len);
    qctx->secret_key = (uint8_t*)malloc(qctx->secret_key_len);

    if (!qctx->public_key || !qctx->secret_key) {
        fprintf(stderr, "Quantum Shield: Failed to allocate key memory.\n");
        free(qctx->public_key); free(qctx->secret_key);
        qctx->public_key = NULL; qctx->secret_key = NULL;
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }
    memset(qctx->public_key, 0xAA, qctx->public_key_len); // Example key data
    memset(qctx->secret_key, 0xBB, qctx->secret_key_len); // Example key data

    printf("Quantum Shield: Keys generated.\n");
    pthread_rwlock_unlock(&qctx->key_lock);

    // --- NEW FEATURE: Quantum Backup ---
    if (atomic_load(&get_security_system_instance()->crash_config.quantum_backup_enabled)) {
        printf("Quantum Shield: Performing quantum key backup.\n");
        // In a real system, this would securely store the keys (e.g., to HSM, encrypted storage)
    }
    return SECURITY_SUCCESS;
}

static security_result_t quantum_encrypt_data(quantum_context_t* qctx, const uint8_t* plaintext, size_t plaintext_len, uint8_t** ciphertext, size_t* ciphertext_len) {
    printf("Quantum Shield: Encrypting data.\n");
    if (!qctx || !plaintext || !ciphertext || !ciphertext_len) return SECURITY_ERROR_INVALID_ARGS;
    pthread_rwlock_rdlock(&qctx->key_lock);
    if (!qctx->public_key) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_QUANTUM_FAILURE; // Keys not generated
    }
    // In a real scenario, actual encryption would occur
    *ciphertext_len = plaintext_len;
    *ciphertext = (uint8_t*)malloc(*ciphertext_len); // Corrected allocation
    if (!*ciphertext) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*ciphertext, plaintext, plaintext_len);
    pthread_rwlock_unlock(&qctx->key_lock);
    return SECURITY_SUCCESS;
}

static security_result_t quantum_decrypt_data(quantum_context_t* qctx, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t** plaintext, size_t* plaintext_len) {
    printf("Quantum Shield: Decrypting data.\n");
    if (!qctx || !ciphertext || !plaintext || !plaintext_len) return SECURITY_ERROR_INVALID_ARGS;
    pthread_rwlock_rdlock(&qctx->key_lock);
    if (!qctx->secret_key) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_QUANTUM_FAILURE; // Keys not generated
    }
    // In a real scenario, actual decryption would occur
    *plaintext_len = ciphertext_len;
    *plaintext = (uint8_t*)malloc(*plaintext_len); // Corrected allocation
    if (!*plaintext) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*plaintext, ciphertext, ciphertext_len);
    pthread_rwlock_unlock(&qctx->key_lock);
    return SECURITY_SUCCESS;
}

static security_result_t quantum_sign_data(quantum_context_t* qctx, const uint8_t* data, size_t data_len, uint8_t** signature, size_t* sig_len) {
    printf("Quantum Shield: Signing data.\n");
    if (!qctx || !data || !signature || !sig_len) return SECURITY_ERROR_INVALID_ARGS;
    pthread_rwlock_rdlock(&qctx->key_lock);
    if (!qctx->secret_key) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_QUANTUM_FAILURE; // Keys not generated
    }
    // In a real scenario, actual signing would occur
    const char* example_sig = "EXAMPLE_QUANTUM_SIGNATURE";
    *sig_len = strlen(example_sig) + 1;
    *signature = (uint8_t*)malloc(*sig_len); // Corrected allocation
    if (!*signature) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*signature, example_sig, *sig_len);
    pthread_rwlock_unlock(&qctx->key_lock);
    return SECURITY_SUCCESS;
}

static security_result_t quantum_verify_signature(quantum_context_t* qctx, const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len) {
    printf("Quantum Shield: Verifying signature.\n");
    if (!qctx || !data || !signature || sig_len == 0) return SECURITY_ERROR_INVALID_ARGS;
    pthread_rwlock_rdlock(&qctx->key_lock);
    if (!qctx->public_key) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_ERROR_QUANTUM_FAILURE; // Keys not generated
    }
    // In a real scenario, actual verification would occur
    const char* example_sig = "EXAMPLE_QUANTUM_SIGNATURE";
    if (sig_len == strlen(example_sig) + 1 && strcmp((const char*)signature, example_sig) == 0) {
        pthread_rwlock_unlock(&qctx->key_lock);
        return SECURITY_SUCCESS;
    }
    pthread_rwlock_unlock(&qctx->key_lock);
    return SECURITY_ERROR_CRYPTO_OPERATION; // Signature mismatch
}

// Quantum Shield operations for detection and cache protection
static security_result_t quantum_detect_quantum_anomalies(void) {
    printf("Quantum Shield: Detecting quantum anomalies for advanced attacks.\n");
    // In a real system, this would involve complex quantum-resistant algorithms
    // and hardware interactions to detect subtle anomalies.
    return SECURITY_SUCCESS;
}

static security_result_t quantum_protect_cache(void* cache_address, size_t cache_size) {
    printf("Quantum Shield: Protecting cache at %p with size %zu.\n", cache_address, cache_size);
    // In a real scenario, this would involve cache partitioning, flushing, or encryption
    // using quantum-resistant methods.
    if (cache_address == NULL || cache_size == 0) return SECURITY_ERROR_INVALID_ARGS;
    atomic_fetch_add(&get_security_system_instance()->modules.quantum_shield.quantum_protection_cycles, 1);
    return SECURITY_SUCCESS;
}

// Quantum Shield dedicated thread function
static void* quantum_shield_thread_func(void* arg) {
    quantum_shield_t* qs = (quantum_shield_t*)arg;
    if (!qs) return NULL;

    printf("[Quantum Shield Thread] Quantum Shield thread started.\n");
    while (atomic_load(&qs->thread_running)) {
        pthread_mutex_lock(&qs->thread_lock);
        // Wait for a trigger or a periodic interval
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5; // Check every 5 seconds or on trigger
        pthread_cond_timedwait(&qs->thread_cond, &qs->thread_lock, &ts);

        if (!atomic_load(&qs->thread_running)) {
            pthread_mutex_unlock(&qs->thread_lock);
            break;
        }

        if (atomic_exchange(&qs->trigger_anomaly_detection, false)) {
            qs->detect_quantum_anomalies();
        }
        if (atomic_exchange(&qs->trigger_cache_protection, false)) {
            // Example: protect a dummy cache region
            qs->protect_cache((void*)0x10000000, 4096);
        }

        // Periodic background tasks
        if (atomic_load(&qs->active)) {
            qs->detect_quantum_anomalies(); // Continuous background detection
            // qs->protect_cache(some_critical_cache_region, size); // Continuous cache protection
        }
        pthread_mutex_unlock(&qs->thread_lock);
    }
    printf("[Quantum Shield Thread] Quantum Shield thread stopped.\n");
    return NULL;
}

// --- Event Stream Operations ---
static void event_stream_subscribe(security_event_type_t type, void (*callback)(event_stream_entry_t*)) {
    printf("Event Stream: Subscribed to event type %d.\n", type);
    // In a real system, this would register the callback for the given event type.
    // For this example, the GUI callback is directly called by the processing thread.
}

static void event_stream_publish(security_event_type_t type, const char* message) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys || !atomic_load(&sys->event_stream.processing_active)) {
        fprintf(stderr, "Event Stream: Not initialized or processing inactive. Event dropped.\n");
        return;
    }

    event_queue_node_t* new_node = (event_queue_node_t*)malloc(sizeof(event_queue_node_t));
    if (!new_node) {
        fprintf(stderr, "Event Stream: Failed to allocate memory for new event node.\n");
        return;
    }

    new_node->entry.event_type = type;
    // --- IMPROVEMENT: Buffer Overflow Mitigation for fixed-length strings ---
    strncpy(new_node->entry.details, message, sizeof(new_node->entry.details) - 1);
    new_node->entry.details[sizeof(new_node->entry.details) - 1] = '\0';
    new_node->entry.timestamp = time(NULL);
    new_node->next = NULL;

    pthread_mutex_lock(&sys->event_stream.queue_lock);
    if (sys->event_stream.tail == NULL) {
        sys->event_stream.head = new_node;
        sys->event_stream.tail = new_node;
    } else {
        sys->event_stream.tail->next = new_node;
        sys->event_stream.tail = new_node;
    }
    pthread_cond_signal(&sys->event_stream.queue_cond); // Signal the processing thread
    pthread_mutex_unlock(&sys->event_stream.queue_lock);

    // Also add to historical log (if needed, protected by its own lock)
    pthread_mutex_lock(&sys->event_stream.lock);
    if (sys->event_stream.count >= sys->event_stream.capacity) {
        // Simple overflow handling: discard oldest or reallocate
        // For this example, we'll just print a warning
        fprintf(stderr, "Event Stream: Historical log capacity reached. Event not stored.\n");
    } else {
        memcpy(&sys->event_stream.entries[sys->event_stream.count], &new_node->entry, sizeof(event_stream_entry_t));
        sys->event_stream.count++;
    }
    pthread_mutex_unlock(&sys->event_stream.lock);

    printf("Event Stream: Published event type %d: %s (queued for processing)\n", type, message);
}

// --- Module Operation Implementations ---

// Messenger
static bool module_messenger_connect_mqtt_tls(const char* broker_addr, int port, const char* cert_path) {
    printf("[Messenger] Attempting to connect to MQTT broker %s:%d with TLS using cert %s.\n", broker_addr, port, cert_path);
    // Dummy implementation: always succeed
    return true;
}
static void module_messenger_send_secure_message(const char* topic, const char* message) {
    printf("[Messenger] Sending secure MQTT message to topic '%s': '%s'\n", topic, message);
    get_security_system_instance()->event_stream.publish(EVENT_SECURE_MESSAGE_SENT, topic);
}
static void module_messenger_send_alert(security_event_type_t event, const char* message) {
    printf("[Messenger] Sending alert for event %d: %s\n", event, message);
    module_messenger_send_secure_message("alerts/critical", message); // Use secure messaging
}
static void module_messenger_notify(const char* subsystem, const char* message) {
    printf("[Messenger] Notification from %s: %s\n", subsystem, message);
}
static void module_messenger_broadcast(security_event_type_t event) {
    printf("[Messenger] Broadcasting event %d\n", event);
}

// --- NEW FEATURE: Neighbor Sync for Crash Resistance ---
static void module_messenger_sync_with_neighbors(void) {
    castle_security_system_t* sys = get_security_system_instance();
    if (atomic_load(&sys->crash_config.neighbor_sync_enabled)) {
        printf("[Messenger] Synchronizing state with neighbor nodes...\n");
        // In a real system, this would involve exchanging heartbeat, configuration,
        // and critical state data with other instances in a cluster.
    } else {
        printf("[Messenger] Neighbor synchronization is disabled.\n");
    }
}

// Internal Monitor
static void module_internal_monitor_health_check(void) {
    printf("[Internal Monitor] Performing health check.\n");
}
static void module_internal_monitor_integrity_verification(void) {
    printf("[Internal Monitor] Performing integrity verification.\n");
}
static void module_internal_monitor_dependency_check(void) {
    printf("[Internal Monitor] Performing dependency check.\n");
}
// Internal module protection
static void internal_monitor_self_integrity_check(void) {
    printf("[Internal Monitor] Performing self-integrity check.\n");
    // In a real system, this would involve cryptographic checksums and comparison
    // against known good values.
}
static void internal_monitor_module_tamper_detection(void) {
    printf("[Internal Monitor] Detecting module tampering.\n");
    // In a real system, this would involve monitoring memory regions, file integrity,
    // and process behavior for signs of tampering.
}
// Internal Monitor dedicated thread function
static void* internal_monitor_thread_func(void* arg) {
    internal_monitor_t* im = (internal_monitor_t*)arg;
    if (!im) return NULL;

    printf("[Internal Monitor Thread] Internal Monitor thread started.\n");
    while (atomic_load(&im->thread_running)) {
        pthread_mutex_lock(&im->thread_lock);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10; // Check every 10 seconds or on trigger
        pthread_cond_timedwait(&im->thread_cond, &im->thread_lock, &ts);

        if (!atomic_load(&im->thread_running)) {
            pthread_mutex_unlock(&im->thread_lock);
            break;
        }

        if (atomic_exchange(&im->trigger_integrity_check, false)) {
            im->self_integrity_check();
            im->module_tamper_detection();
        }

        // Periodic background tasks
        if (atomic_load(&im->active)) {
            im->health_check();
            im->integrity_verification();
        }
        pthread_mutex_unlock(&im->thread_lock);
    }
    printf("[Internal Monitor Thread] Internal Monitor thread stopped.\n");
    return NULL;
}

// Recovery
static void module_recovery_module_recovery(void) {
    printf("[Recovery] Initiating module recovery.\n");
}
static void module_recovery_system_rollback(void) {
    printf("[Recovery] Initiating system rollback.\n");
}
static void module_recovery_state_restoration(void) {
    printf("[Recovery] Initiating state restoration.\n");
}
static void module_recovery_create_snapshot(const char* config_name) {
    printf("[Recovery] Creating configuration snapshot: %s\n", config_name);
    get_security_system_instance()->event_stream.publish(EVENT_SYSTEM_RESTORED, "Configuration snapshot created.");
}
static void module_recovery_restore_from_snapshot(const char* config_name) {
    printf("[Recovery] Restoring system from snapshot: %s\n", config_name);
    get_security_system_instance()->event_stream.publish(EVENT_SYSTEM_RESTORED, "System restored from snapshot.");
}
static void module_recovery_manage_vulnerabilities(void) {
    printf("[Recovery] Scanning for and managing system vulnerabilities.\n");
    get_security_system_instance()->event_stream.publish(EVENT_VULNERABILITY_DETECTED, "Vulnerability scan completed.");
}
static void module_recovery_apply_patches(void) {
    printf("[Recovery] Applying necessary security patches.\n");
    get_security_system_instance()->event_stream.publish(EVENT_PATCH_APPLIED, "Security patches applied.");
}

// --- NEW FEATURE: Periodic Backup Thread for Crash Resistance ---
static void* recovery_backup_thread_func(void* arg) {
    recovery_t* rec = (recovery_t*)arg;
    if (!rec) return NULL;

    printf("[Recovery Backup Thread] Backup thread started.\n");
    while (atomic_load(&rec->backup_thread_running)) {
        pthread_mutex_lock(&rec->backup_thread_lock);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += rec->backup_interval_seconds; // Wait for configured interval
        pthread_cond_timedwait(&rec->backup_thread_cond, &rec->backup_thread_lock, &ts);

        if (!atomic_load(&rec->backup_thread_running)) {
            pthread_mutex_unlock(&rec->backup_thread_lock);
            break;
        }

        if (atomic_load(&rec->active)) {
            printf("[Recovery Backup Thread] Performing scheduled backup...\n");
            rec->create_snapshot("Scheduled_Backup");
            rec->last_backup_time = time(NULL);
        }
        pthread_mutex_unlock(&rec->backup_thread_lock);
    }
    printf("[Recovery Backup Thread] Backup thread stopped.\n");
    return NULL;
}

// System Protector
static void module_system_protector_scan(void) {
    printf("[System Protector] Performing system scan.\n");
}
static void module_system_protector_quarantine(void) {
    printf("[System Protector] Quarantining detected threats.\n");
}
static void module_system_protector_analysis(void) {
    printf("[System Protector] Performing threat analysis.\n");
}
// System Protector dedicated thread function
static void* system_protector_thread_func(void* arg) {
    system_protector_t* sp = (system_protector_t*)arg;
    if (!sp) return NULL;

    printf("[System Protector Thread] System Protector thread started.\n");
    while (atomic_load(&sp->thread_running)) {
        pthread_mutex_lock(&sp->thread_lock);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 30; // Scan every 30 seconds or on trigger
        pthread_cond_timedwait(&sp->thread_cond, &sp->thread_lock, &ts);

        if (!atomic_load(&sp->thread_running)) {
            pthread_mutex_unlock(&sp->thread_lock);
            break;
        }

        if (atomic_exchange(&sp->trigger_scan, false)) {
            sp->scan();
            sp->analysis();
            sp->quarantine();
        }

        // Periodic background tasks
        if (atomic_load(&sp->active)) {
            sp->scan(); // Continuous background scanning
        }
        pthread_mutex_unlock(&sp->thread_lock);
    }
    printf("[System Protector Thread] System Protector thread stopped.\n");
    return NULL;
}

// Firewall Storage
static void firewall_storage_add(const char* rule, security_rule_type_t type, const char* description) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;
    pthread_rwlock_wrlock(&sys->modules.firewall_storage.list_lock); // Acquire write lock
    printf("[Firewall Storage] Adding rule: %s (Type: %d, Desc: %s)\n", rule, type, description);
    security_list_add(&sys->modules.firewall_storage.blacklist, rule, type, description); // Example: add to blacklist
    atomic_fetch_add(&sys->modules.firewall_storage.rule_count, 1);
    pthread_rwlock_unlock(&sys->modules.firewall_storage.list_lock); // Release write lock
    sys->event_stream.publish(EVENT_POLICY_UPDATE, "Firewall rule added.");
}
static void firewall_storage_remove(const char* rule, security_rule_type_t type) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;
    pthread_rwlock_wrlock(&sys->modules.firewall_storage.list_lock); // Acquire write lock
    printf("[Firewall Storage] Removing rule: %s (Type: %d)\n", rule, type);
    // Real implementation would search and remove from lists
    pthread_rwlock_unlock(&sys->modules.firewall_storage.list_lock); // Release write lock
    sys->event_stream.publish(EVENT_POLICY_UPDATE, "Firewall rule removed.");
}
static void firewall_storage_update(const char* rule, security_rule_type_t type, const char* new_description) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;
    pthread_rwlock_wrlock(&sys->modules.firewall_storage.list_lock); // Acquire write lock
    printf("[Firewall Storage] Updating rule: %s (Type: %d, New Desc: %s)\n", rule, type, new_description);
    // Real implementation would search and update in lists
    pthread_rwlock_unlock(&sys->modules.firewall_storage.list_lock); // Release write lock
    sys->event_stream.publish(EVENT_POLICY_UPDATE, "Firewall rule updated.");
}

// Inspection Unit
static void module_inspection_unit_rule_analysis(void) {
    printf("[Inspection Unit] Performing rule analysis.\n");
}
static void module_inspection_unit_security_enforcement(void) {
    printf("[Inspection Unit] Enforcing security policies.\n");
}
static void module_inspection_unit_policy_optimization(void) {
    printf("[Inspection Unit] Optimizing security policies.\n");
}
static void module_inspection_unit_reporting(void) {
    printf("[Inspection Unit] Generating reports.\n");
}

// Kernel Bridge
static void module_kernel_bridge_sync(void) {
    printf("[Kernel Bridge] Synchronizing with kernel.\n");
}
static void module_kernel_bridge_alert(const char* message) {
    printf("[Kernel Bridge] Alert from kernel: %s\n", message);
}
static void module_kernel_bridge_command_handler(void) {
    printf("[Kernel Bridge] Handling kernel command.\n");
}
static void module_kernel_bridge_secure_ipc_send(const void* data, size_t size) {
    printf("[Kernel Bridge] Sending %zu bytes securely to kernel via IPC.\n", size);
    // In a real system, this would use a secure IPC mechanism (e.g., netlink, vsock with encryption)
}
static bool module_kernel_bridge_validate_ipc_message(const void* message, size_t size) {
    printf("[Kernel Bridge] Validating incoming IPC message of %zu bytes.\n", size);
    // In a real system, this would involve cryptographic signatures, MACs, or strict schema validation
    return true; // Dummy: always valid
}

// Sandboxing
static void module_sandbox_create(const char* name, const char* base_dir) {
    printf("[Sandbox] Creating sandbox '%s' at '%s'.\n", name, base_dir);
    // In a real system, this would involve:
    // 1. Creating a new mount namespace (unshare(CLONE_NEWNS))
    // 2. Chrooting to base_dir (chroot(base_dir))
    // 3. Changing UID/GID to isolated_uid/gid (setresuid, setresgid)
    // 4. Applying seccomp filters for allowed_syscalls (seccomp_load)
    // 5. Potentially creating a new PID, network, or IPC namespace.
}
static void module_sandbox_destroy(const char* name) {
    printf("[Sandbox] Destroying sandbox '%s'.\n", name);
    // In a real system, this would involve cleaning up namespaces, unmounting, etc.
}
static bool sandbox_execute_in_sandbox(const char* sandbox_name, const char* command) {
    printf("[Sandbox] Executing '%s' in sandbox '%s'.\n", command, sandbox_name);
    // In a real system, this would involve forking a process and executing 'command'
    // within the context of the created sandbox (chroot, uid/gid, seccomp, namespaces).
    return true;
}
static void module_sandbox_update_policy(const char* sandbox_name) {
    printf("[Sandbox] Updating policy for sandbox '%s'.\n", sandbox_name);
}
static void module_sandbox_monitor_activity(const char* sandbox_name) {
    printf("[Sandbox] Monitoring activity in sandbox '%s'.\n", sandbox_name);
}

// Castle Journal
static void module_castle_journal_record(security_event_type_t event, const char* details) {
    printf("[Castle Journal] Recording event %d: %s\n", event, details);
}
static void module_castle_journal_retrieve(time_t from, time_t to) {
    printf("[Castle Journal] Retrieving logs from %ld to %ld.\n", (long)from, (long)to);
}
static void module_castle_journal_analyze(void) {
    printf("[Castle Journal] Analyzing logs.\n");
}
static void module_castle_journal_compress(void) {
    printf("[Castle Journal] Compressing logs with advanced algorithms.\n");
}
static void module_castle_journal_integrate_siem(const char* siem_endpoint) {
    printf("[Castle Journal] Integrating with SIEM system at %s.\n", siem_endpoint);
}

// Firewall
static void module_firewall_process_packet(void* pkt) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;

    // Protect access to sk_buff (pkt) to prevent race conditions and double access
    pthread_mutex_lock(&sys->modules.firewall.sk_buff_lock);
    printf("[Firewall] Processing packet (protected by mutex).\n");
    // In a real kernel, this would involve accessing sk_buff fields.
    // For user-space, we just simulate the protected access.
    // Example: if (pkt->len > MAX_PACKET_SIZE) { ... }
    pthread_mutex_unlock(&sys->modules.firewall.sk_buff_lock);
}

// Castle Wall
static void module_castle_wall_access_monitor(void) {
    printf("[Castle Wall] Monitoring access.\n");
}
static void module_castle_wall_intrusion_prevention(void) {
    printf("[Castle Wall] Preventing intrusion.\n");
}
static void module_castle_wall_threat_assessment(void) {
    printf("[Castle Wall] Assessing threats.\n");
}

// Watch Tower
static void module_watch_tower_threat_detection(void) {
    printf("[Watch Tower] Performing threat detection.\n");
}
static void module_watch_tower_alert_handling(security_event_type_t event) {
    printf("[Watch Tower] Handling alert for event %d.\n", event);
}
static void module_watch_tower_anomaly_detection(void) {
    printf("[Watch Tower] Detecting anomalies.\n");
}

// Patrol
static void module_patrol_data_scan(void) {
    printf("[Patrol] Scanning data.\n");
}
static void module_patrol_suspicious_activity_handler(void) {
    printf("[Patrol] Handling suspicious activity.\n");
}
static void module_patrol_log_activity(security_event_type_t event) {
    printf("[Patrol] Logging activity for event %d.\n", event);
}
// Lateral Movement Detection
static void patrol_detect_lateral_movement(void) {
    printf("[Patrol] Detecting lateral movement. This operation benefits from continuous training and fine-tuning.\n");
    // In a real system, this would involve network flow analysis, process monitoring,
    // and behavioral analytics to identify lateral movement.
    get_security_system_instance()->event_stream.publish(EVENT_LATERAL_MOVEMENT_DETECTED, "Potential lateral movement detected.");
}
static void patrol_respond_lateral_movement(void) {
    printf("[Patrol] Responding to lateral movement. Response effectiveness depends on detection tuning.\n");
    // In a real system, this would involve isolating the compromised host,
    // blocking suspicious network connections, and alerting administrators.
    get_security_system_instance()->modules.firewall_storage.add("suspicious_internal_ip", RULE_IP_BASED, "Blocked due to lateral movement");
    get_security_system_instance()->modules.messenger.send_alert(EVENT_SECURITY_BREACH, "Automated response to lateral movement initiated.");
}
// Patrol training and tuning functions
static void patrol_train_detection_model(const void* real_data, size_t data_size) {
    printf("[Patrol] Training lateral movement detection model with real data (size: %zu bytes).\n", data_size);
    atomic_fetch_add(&get_security_system_instance()->modules.patrol.training_data_processed, data_size);
    // In a real system, this would involve feeding actual network/system logs
    // into a machine learning model or rule engine to improve its accuracy.
}

static void patrol_fine_tune_detection_parameters(int level) {
    printf("[Patrol] Fine-tuning lateral movement detection parameters to level %d.\n", level);
    get_security_system_instance()->modules.patrol.tuning_level = level;
    // In a real system, this would adjust thresholds, sensitivity, or specific rule weights
    // based on operational feedback or new threat intelligence.
}

// --- NEW FEATURE: Dynamic Workload Adjustment for Patrol ---
static void patrol_set_workload_level(int level) {
    patrol_t* patrol = &get_security_system_instance()->modules.patrol;
    if (level < 0 || level > 3) {
        fprintf(stderr, "[Patrol] Invalid workload level: %d. Must be 0-3.\n", level);
        return;
    }
    atomic_store(&patrol->workload_level, level);
    printf("[Patrol] Workload level set to %d.\n", level);
    // In a real system, this would dynamically adjust scan frequency, CPU usage,
    // or network bandwidth allocated to patrol activities.
}

// Patrol dedicated thread function
static void* patrol_thread_func(void* arg) {
    patrol_t* patrol = (patrol_t*)arg;
    if (!patrol) return NULL;

    printf("[Patrol Thread] Patrol thread started.\n");
    while (atomic_load(&patrol->thread_running)) {
        pthread_mutex_lock(&patrol->thread_lock);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int sleep_duration = 7; // Default
        switch (atomic_load(&patrol->workload_level)) {
            case 0: sleep_duration = 60; break; // Idle: check every minute
            case 1: sleep_duration = 30; break; // Low: check every 30 seconds
            case 2: sleep_duration = 10; break; // Medium: check every 10 seconds
            case 3: sleep_duration = 3; break;  // High: check every 3 seconds
        }
        ts.tv_sec += sleep_duration;
        pthread_cond_timedwait(&patrol->thread_cond, &patrol->thread_lock, &ts);

        if (!atomic_load(&patrol->thread_running)) {
            pthread_mutex_unlock(&patrol->thread_lock);
            break;
        }

        if (atomic_exchange(&patrol->trigger_detection, false)) {
            patrol->detect_lateral_movement();
        }

        // Periodic background tasks based on workload
        if (atomic_load(&patrol->active)) {
            patrol->data_scan(); // Continuous background data scanning
            patrol->detect_lateral_movement(); // Continuous background detection
        }
        pthread_mutex_unlock(&patrol->thread_lock);
    }
    printf("[Patrol Thread] Patrol thread stopped.\n");
    return NULL;
}

// Guardian
static void module_guardian_encrypt_data(void* data, size_t size) {
    printf("[Guardian] Encrypting data of size %zu.\n", size);
}
static void module_guardian_decrypt_data(void* data, size_t size) {
    printf("[Guardian] Decrypting data of size %zu.\n", size);
}
static void module_guardian_access_control(void) {
    printf("[Guardian] Enforcing access control.\n");
}
static bool module_guardian_load_key_from_tpm(uint8_t* key_buffer, size_t buffer_size) {
    printf("[Guardian] Loading key from TPM (Trusted Platform Module).\n");
    // Dummy implementation: fill buffer with some data
    if (key_buffer && buffer_size > 0) {
        memset(key_buffer, 0xDE, buffer_size);
        return true;
    }
    return false;
}
static bool module_guardian_generate_key_in_hsm(uint32_t key_id) {
    printf("[Guardian] Generating key %u in HSM (Hardware Security Module).\n", key_id);
    // Dummy implementation: always succeed
    return true;
}

// Security Unit
static void module_security_unit_attack_mitigation(void) {
    printf("[Security Unit] Mitigating attack.\n");
}
static void module_security_unit_resource_protection(void) {
    printf("[Security Unit] Protecting resources.\n");
}
static void module_security_unit_emergency_response(void) {
    printf("[Security Unit] Initiating emergency response.\n");
}
static void module_security_unit_automate_response(security_event_type_t event) {
    printf("[Security Unit] Automating response for event type %d (SOAR).\n", event);
    get_security_system_instance()->event_stream.publish(EVENT_SOAR_RESPONSE_INITIATED, "Automated response triggered.");
}
static void module_security_unit_orchestrate_incident_response(void) {
    printf("[Security Unit] Orchestrating complex incident response workflow (SOAR).\n");
}

// Witch
static void module_witch_device_registration(void) {
    printf("[Witch] Registering device.\n");
}
static void module_witch_traffic_monitoring(void) {
    printf("[Witch] Monitoring network traffic.\n");
}
static void module_witch_policy_enforcement(void) {
    printf("[Witch] Enforcing network policy.\n");
}

// Arcane Scan
static bool arcane_scan_verify_with_token(void) {
    printf("[Arcane Scan] Verifying with token.\n");
    return true;
}
static bool arcane_scan_biometric_authentication(void) {
    printf("[Arcane Scan] Performing biometric authentication.\n");
    return true;
}
static bool arcane_scan_location_based_verification(void) {
    printf("[Arcane Scan] Performing location-based verification.\n");
    return true;
}

// Cipher Sentinel
static void module_cipher_sentinel_secure_key_generation(void) {
    printf("[Cipher Sentinel] Generating secure keys.\n");
}
static void module_cipher_sentinel_real_time_cipher_monitoring(void) {
    printf("[Cipher Sentinel] Monitoring ciphers in real-time.\n");
}
static void module_cipher_sentinel_decryption_protection(void) {
    printf("[Cipher Sentinel] Providing decryption protection.\n");
}

// Signature Verification
static bool module_signature_verification_verify_post_quantum_signature(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len) {
    printf("[Signature Verification] Verifying post-quantum signature for %zu bytes of data.\n", data_len);
    // Dummy implementation: always true
    return true;
}

// Shadow Gatekeeper
static void module_shadow_gatekeeper_load_wasm_filter(const char* wasm_bytecode) {
    printf("[Shadow Gatekeeper] Loading WASM filter (bytecode size: %zu).\n", strlen(wasm_bytecode));
    // In a real system, this would initialize a WASM runtime and load the module.
    atomic_store(&get_security_system_instance()->modules.shadow_gatekeeper.wasm_enabled, true);
    get_security_system_instance()->modules.shadow_gatekeeper.wasm_module_handle = (void*)1; // Dummy handle
}
static void module_shadow_gatekeeper_unload_wasm_filter(void) {
    printf("[Shadow Gatekeeper] Unloading WASM filter.\n");
    // In a real system, this would shut down the WASM runtime and free resources.
    atomic_store(&get_security_system_instance()->modules.shadow_gatekeeper.wasm_enabled, false);
    get_security_system_instance()->modules.shadow_gatekeeper.wasm_module_handle = NULL;
}
static void module_shadow_gatekeeper_process_with_wasm(void* data, size_t size) {
    pthread_mutex_lock(&get_security_system_instance()->modules.shadow_gatekeeper.gatekeeper_lock);
    printf("[Shadow Gatekeeper] Processing %zu bytes of data with WASM filter in sandbox.\n", size);
    // In a real system, this would pass data to the WASM module for sandboxed execution.
    pthread_mutex_unlock(&get_security_system_instance()->modules.shadow_gatekeeper.gatekeeper_lock);
}

// Secure Boot
static bool secure_boot_verify_hardware(void) {
    printf("[Secure Boot] Verifying hardware.\n");
    return true;
}
static bool secure_boot_verify_firmware(void) {
    printf("[Secure Boot] Verifying firmware.\n");
    return true;
}
static bool secure_boot_verify_kernel(void) {
    printf("[Secure Boot] Verifying kernel.\n");
    return true;
}
static bool secure_boot_verify_boot_chain(void) {
    printf("[Secure Boot] Verifying boot chain.\n");
    return true;
}
static void module_secure_boot_recovery_boot(void) {
    printf("[Secure Boot] Initiating recovery boot.\n");
}

// Phantom Hand
static void module_phantom_hand_configure_fpga(void) {
    printf("[Phantom Hand] Configuring FPGA.\n");
}
static void module_phantom_hand_program_asic(void) {
    printf("[Phantom Hand] Programming ASIC.\n");
}
static void module_phantom_hand_offload_processing(void* data, size_t size) {
    printf("[Phantom Hand] Offloading processing of %zu bytes to specialized hardware.\n", size);
}
static void module_phantom_hand_dynamic_schedule_tasks(void) {
    printf("[Phantom Hand] Dynamically scheduling tasks for optimal performance.\n");
}
static void module_phantom_hand_optimize_power_consumption(void) {
    printf("[Phantom Hand] Optimizing hardware power consumption.\n");
}

// Wisdom Flow
static void module_wisdom_flow_apply_backport(const char* feature) {
    printf("[Wisdom Flow] Applying backport for feature '%s'.\n", feature);
}
static void module_wisdom_flow_verify_compatibility(void) {
    printf("[Wisdom Flow] Verifying compatibility.\n");
}
static void module_wisdom_flow_rollback_changes(void) {
    printf("[Wisdom Flow] Rolling back changes.\n");
}

// Grumpy Frame
static void module_grumpy_frame_create_hardware_sandbox(void) {
    printf("[Grumpy Frame] Creating hardware sandbox.\n");
}
static void module_grumpy_frame_isolate_process(pid_t pid) {
    printf("[Grumpy Frame] Isolating process with PID %d.\n", pid);
    // In a real system, this would involve hardware virtualization extensions (e.g., Intel VT-x, AMD-V)
    // or memory protection units (MPU) to create a secure execution environment for the process.
}
static void module_grumpy_frame_monitor_sandbox(void) {
    printf("[Grumpy Frame] Monitoring hardware sandbox.\n");
}

// Fast Barrier
static void module_fast_barrier_load_ebpf_program(const char* program) {
    printf("[Fast Barrier] Loading eBPF program.\n");
    // In a real system, this would load an eBPF bytecode program into the kernel.
}
static void module_fast_barrier_configure_xdp_filter(void) {
    printf("[Fast Barrier] Configuring XDP filter for high-speed packet processing.\n");
    // In a real system, this would attach an XDP program to a network interface.
}
static void module_fast_barrier_optimize_packet_processing(void) {
    printf("[Fast Barrier] Optimizing packet processing using XDP/eBPF.\n");
}

// Lazy Zoom
static void module_lazy_zoom_distribute_traffic(void) {
    printf("[Lazy Zoom] Distributing traffic.\n");
}
static void module_lazy_zoom_add_server_node(const char* node_address) {
    printf("[Lazy Zoom] Adding server node '%s'.\n", node_address);
}
static void module_lazy_zoom_remove_server_node(const char* node_address) {
    printf("[Lazy Zoom] Removing server node '%s'.\n", node_address);
}
static void module_lazy_zoom_apply_load_balancing(void) {
    printf("[Lazy Zoom] Applying intelligent load balancing algorithms.\n");
}
static void module_lazy_zoom_self_tune_system(void) {
    printf("[Lazy Zoom] Self-tuning system parameters for optimal performance.\n");
}

// Granite
static void module_granite_initialize_sgx(void) {
    printf("[Granite] Initializing SGX.\n");
}
static void module_granite_setup_sev(void) {
    printf("[Granite] Setting up SEV.\n");
}
static void module_granite_create_secure_enclave(void* data, size_t size) {
    printf("[Granite] Creating secure enclave with data size %zu.\n", size);
}

// Spectre and Timing Attack Defense Module Operations
static void spectre_timing_enable_mitigations(void) {
    printf("[Spectre/Timing Defense] Enabling mitigations.\n");
    // In a real system, this would involve setting CPU MSRs, kernel flags, or using specific compiler flags.
}
static void spectre_timing_disable_mitigations(void) {
    printf("[Spectre/Timing Defense] Disabling mitigations.\n");
}
static void spectre_timing_detect_spectre_attack(void) {
    printf("[Spectre/Timing Defense] Detecting Spectre attack.\n");
    atomic_fetch_add(&get_security_system_instance()->modules.spectre_timing_defense.mitigated_attacks_count, 1);
    get_security_system_instance()->event_stream.publish(EVENT_INTRUSION_ATTEMPT, "Spectre attack detection routine executed.");
}
static void spectre_timing_detect_timing_attack(void) {
    printf("[Spectre/Timing Defense] Detecting Timing attack.\n");
    atomic_fetch_add(&get_security_system_instance()->modules.spectre_timing_defense.mitigated_attacks_count, 1);
    get_security_system_instance()->event_stream.publish(EVENT_INTRUSION_ATTEMPT, "Timing attack detection routine executed.");
}
static void spectre_timing_apply_speculative_execution_hardening(void) {
    printf("[Spectre/Timing Defense] Applying speculative execution hardening.\n");
}
static void spectre_timing_apply_timing_noise(void) {
    printf("[Spectre/Timing Defense] Applying timing noise.\n");
}
// Spectre/Timing Defense dedicated thread function
static void* spectre_timing_defense_thread_func(void* arg) {
    spectre_timing_defense_t* std = (spectre_timing_defense_t*)arg;
    if (!std) return NULL;

    printf("[Spectre/Timing Defense Thread] Spectre/Timing Defense thread started.\n");
    while (atomic_load(&std->thread_running)) {
        pthread_mutex_lock(&std->thread_lock);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 3; // Detect every 3 seconds or on trigger
        pthread_cond_timedwait(&std->thread_cond, &std->thread_lock, &ts);

        if (!atomic_load(&std->thread_running)) {
            pthread_mutex_unlock(&std->thread_lock);
            break;
        }

        if (atomic_exchange(&std->trigger_detection, false)) {
            std->detect_spectre_attack();
            std->detect_timing_attack();
        }

        // Periodic background tasks
        if (atomic_load(&std->active)) {
            std->detect_spectre_attack(); // Continuous background detection
            std->detect_timing_attack();
        }
        pthread_mutex_unlock(&std->thread_lock);
    }
    printf("[Spectre/Timing Defense Thread] Spectre/Timing Defense thread stopped.\n");
    return NULL;
}

// Fairshare Warden
static void module_fairshare_warden_monitor_resource_usage(void) {
    printf("[Fairshare Warden] Monitoring resource usage.\n");
    // In a real system, this would query kernel cgroups or other resource monitoring APIs.
    // Example: Check current CPU/memory usage for each group.
    fairshare_warden_t* fw = &get_security_system_instance()->modules.fairshare_warden;
    pthread_rwlock_rdlock(&fw->policy_lock);
    for (size_t i = 0; i < fw->policy_count; ++i) {
        printf("  Group '%s': CPU %.2f%%, Mem %zuKB, IO %zuKB/s (simulated)\n",
               fw->group_policies[i].group_id,
               fw->group_policies[i].cpu_share * 100.0,
               fw->group_policies[i].memory_limit / 1024,
               fw->group_policies[i].io_bandwidth / 1024);
    }
    pthread_rwlock_unlock(&fw->policy_lock);
}

static void module_fairshare_warden_enforce_fairshare_rules(void) {
    printf("[Fairshare Warden] Enforcing fairshare rules.\n");
    // In a real system, this would apply cgroup limits, scheduler priorities, etc.
    fairshare_warden_t* fw = &get_security_system_instance()->modules.fairshare_warden;
    pthread_rwlock_rdlock(&fw->policy_lock);
    for (size_t i = 0; i < fw->policy_count; ++i) {
        printf("  Applying rules for group '%s': CPU %.2f%%, Mem %zuKB, IO %zuKB/s (simulated enforcement)\n",
               fw->group_policies[i].group_id,
               fw->group_policies[i].cpu_share * 100.0,
               fw->group_policies[i].memory_limit / 1024,
               fw->group_policies[i].io_bandwidth / 1024);
    }
    pthread_rwlock_unlock(&fw->policy_lock);
}

static void module_fairshare_warden_adjust_resource_allocation(const char* group_id, int priority) {
    printf("[Fairshare Warden] Adjusting resource allocation for group '%s' to priority %d.\n", group_id, priority);
}
static void module_fairshare_warden_detect_violations(void) {
    printf("[Fairshare Warden] Detecting violations.\n");
    // Simulate a violation
    if (rand() % 10 == 0) { // 10% chance of violation
        get_security_system_instance()->event_stream.publish(EVENT_RESOURCE_QUOTA_VIOLATION, "CPU quota exceeded for 'HighPriorityGroup'");
    }
}
static void module_fairshare_warden_report_usage_statistics(void) {
    printf("[Fairshare Warden] Reporting usage statistics.\n");
}
static void module_fairshare_warden_update_gui_display(void) {
    printf("[Fairshare Warden] Updating GUI display.\n");
}
static void module_fairshare_warden_enforce_qos(void) {
    printf("[Fairshare Warden] Enforcing Quality of Service policies.\n");
}
static void module_fairshare_warden_get_realtime_metrics(void) {
    printf("[Fairshare Warden] Retrieving real-time resource usage metrics.\n");
}

// --- NEW FEATURE: Set Resource Quota for Fairshare Warden ---
static security_result_t fairshare_warden_set_resource_quota(const char* group_id, double cpu_share, size_t memory_limit, size_t io_bandwidth) {
    fairshare_warden_t* fw = &get_security_system_instance()->modules.fairshare_warden;
    if (!group_id || cpu_share < 0.0 || cpu_share > 1.0 || memory_limit == 0 || io_bandwidth == 0) {
        return SECURITY_ERROR_INVALID_ARGS;
    }

    pthread_rwlock_wrlock(&fw->policy_lock);
    // Check if group already exists, update if so
    for (size_t i = 0; i < fw->policy_count; ++i) {
        if (strcmp(fw->group_policies[i].group_id, group_id) == 0) {
            fw->group_policies[i].cpu_share = cpu_share;
            fw->group_policies[i].memory_limit = memory_limit;
            fw->group_policies[i].io_bandwidth = io_bandwidth;
            printf("[Fairshare Warden] Updated resource quota for group '%s'.\n", group_id);
            pthread_rwlock_unlock(&fw->policy_lock);
            return SECURITY_SUCCESS;
        }
    }

    // Add new group if capacity allows
    if (fw->policy_count < MAX_FAIRSHARE_GROUPS) {
        fairshare_group_policy_t* new_policy = &fw->group_policies[fw->policy_count];
        strncpy(new_policy->group_id, group_id, sizeof(new_policy->group_id) - 1);
        new_policy->group_id[sizeof(new_policy->group_id) - 1] = '\0';
        new_policy->cpu_share = cpu_share;
        new_policy->memory_limit = memory_limit;
        new_policy->io_bandwidth = io_bandwidth;
        new_policy->priority = 5; // Default priority
        fw->policy_count++;
        printf("[Fairshare Warden] Added new resource quota for group '%s'.\n", group_id);
        pthread_rwlock_unlock(&fw->policy_lock);
        return SECURITY_SUCCESS;
    } else {
        fprintf(stderr, "[Fairshare Warden] Max fairshare groups reached. Cannot add '%s'.\n", group_id);
        pthread_rwlock_unlock(&fw->policy_lock);
        return SECURITY_ERROR_RESOURCE_LIMIT_EXCEEDED;
    }
}

// IAM Module
// Dummy password hashing (replace with real bcrypt/argon2 in production)
static void hash_password(const char* password, char* output_hash_hex, size_t output_size) {
    // This is a dummy SHA256 hash. In a real system, use a strong KDF like Argon2 or bcrypt.
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, password, strlen(password));
    // unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256_Final(hash, &sha256);
    // For dummy:
    unsigned char hash[SHA256_DIGEST_LENGTH];
    memset(hash, 0, SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < strlen(password) && i < SHA256_DIGEST_LENGTH; ++i) {
        hash[i] = password[i]; // Very weak dummy hash
    }

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(&output_hash_hex[i * 2], 3, "%02x", hash[i]);
    }
    output_hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}

static bool module_iam_authenticate_user(const char* username, const char* password) {
    printf("[IAM] Authenticating user '%s'.\n", username);
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);

    iam_user_account_t* user = iam->get_user_by_username(username);
    if (user) {
        char hashed_input_password[SHA256_DIGEST_LENGTH * 2 + 1];
        hash_password(password, hashed_input_password, sizeof(hashed_input_password));
        if (strcmp(user->password_hash, hashed_input_password) == 0) {
            atomic_fetch_add(&iam->authenticated_users, 1);
            printf("[IAM] User '%s' authenticated successfully (UID: %u).\n", username, user->uid);
            pthread_mutex_unlock(&iam->user_db_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&iam->user_db_lock);
    get_security_system_instance()->event_stream.publish(EVENT_IAM_AUTH_FAILED, "Authentication failed for user.");
    printf("[IAM] Authentication failed for user '%s'.\n", username);
    return false;
}

static bool module_iam_authorize_action(const char* username, const char* resource, const char* action) {
    printf("[IAM] Authorizing user '%s' for action '%s' on resource '%s'.\n", username, action, resource);
    // Dummy authorization: always true for 'admin', false for 'guest' on 'firewall_rules'
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);
    iam_user_account_t* user = iam->get_user_by_username(username);
    bool authorized = false;
    if (user) {
        if (strcmp(user->role, "admin") == 0) {
            authorized = true;
        } else if (strcmp(user->role, "patrol_role") == 0 && strcmp(resource, "patrol_config") == 0) {
            authorized = true;
        } else if (strcmp(user->role, "guest") == 0 && strcmp(resource, "firewall_rules") == 0 && strcmp(action, "modify") == 0) {
            authorized = false; // Guests cannot modify firewall rules
        } else {
            authorized = true; // Default allow for other cases
        }
    }
    pthread_mutex_unlock(&iam->user_db_lock);
    printf("[IAM] User '%s' %s authorized for '%s' on '%s'.\n", username, authorized ? "IS" : "IS NOT", action, resource);
    return authorized;
}

// --- NEW FEATURE: Add User with Fixed UID ---
static security_result_t module_iam_add_user(const char* username, const char* password, const char* role, uid_t fixed_uid) {
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);

    if (iam->user_count >= sizeof(iam->users) / sizeof(iam_user_account_t)) {
        fprintf(stderr, "[IAM] User database full. Cannot add user '%s'.\n", username);
        pthread_mutex_unlock(&iam->user_db_lock);
        return SECURITY_ERROR_RESOURCE_LIMIT_EXCEEDED;
    }

    // Check if username or fixed_uid already exists
    for (size_t i = 0; i < iam->user_count; ++i) {
        if (strcmp(iam->users[i].username, username) == 0) {
            fprintf(stderr, "[IAM] User '%s' already exists.\n", username);
            pthread_mutex_unlock(&iam->user_db_lock);
            return SECURITY_ERROR_USER_EXISTS;
        }
        if (fixed_uid != 0 && iam->users[i].uid == fixed_uid) { // 0 means auto-assign
            fprintf(stderr, "[IAM] Fixed UID %u already in use.\n", fixed_uid);
            pthread_mutex_unlock(&iam->user_db_lock);
            return SECURITY_ERROR_USER_EXISTS;
        }
    }

    iam_user_account_t* new_user = &iam->users[iam->user_count];
    strncpy(new_user->username, username, sizeof(new_user->username) - 1);
    new_user->username[sizeof(new_user->username) - 1] = '\0';
    strncpy(new_user->role, role, sizeof(new_user->role) - 1);
    new_user->role[sizeof(new_user->role) - 1] = '\0';
    hash_password(password, new_user->password_hash, sizeof(new_user->password_hash));

    if (fixed_uid != 0) {
        new_user->uid = fixed_uid;
        new_user->is_important_user = true;
    } else {
        // Auto-assign UID (simple increment, in real system use a more robust scheme)
        new_user->uid = 2000 + iam->user_count;
        new_user->is_important_user = false;
    }

    iam->user_count++;
    printf("[IAM] Added user '%s' with role '%s' and UID %u.\n", username, role, new_user->uid);
    pthread_mutex_unlock(&iam->user_db_lock);
    return SECURITY_SUCCESS;
}

static security_result_t module_iam_remove_user(const char* username) {
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);

    size_t found_idx = -1;
    for (size_t i = 0; i < iam->user_count; ++i) {
        if (strcmp(iam->users[i].username, username) == 0) {
            found_idx = i;
            break;
        }
    }

    if (found_idx != (size_t)-1) {
        // Shift elements to remove
        for (size_t i = found_idx; i < iam->user_count - 1; ++i) {
            iam->users[i] = iam->users[i + 1];
        }
        iam->user_count--;
        printf("[IAM] Removed user '%s'.\n", username);
        pthread_mutex_unlock(&iam->user_db_lock);
        return SECURITY_SUCCESS;
    } else {
        fprintf(stderr, "[IAM] User '%s' not found.\n", username);
        pthread_mutex_unlock(&iam->user_db_lock);
        return SECURITY_ERROR_USER_NOT_FOUND;
    }
}

// --- NEW FEATURE: Get User by UID/Username ---
static iam_user_account_t* module_iam_get_user_by_uid(uid_t uid) {
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);
    for (size_t i = 0; i < iam->user_count; ++i) {
        if (iam->users[i].uid == uid) {
            pthread_mutex_unlock(&iam->user_db_lock);
            return &iam->users[i];
        }
    }
    pthread_mutex_unlock(&iam->user_db_lock);
    return NULL;
}

static iam_user_account_t* module_iam_get_user_by_username(const char* username) {
    iam_module_t* iam = &get_security_system_instance()->modules.iam;
    pthread_mutex_lock(&iam->user_db_lock);
    for (size_t i = 0; i < iam->user_count; ++i) {
        if (strcmp(iam->users[i].username, username) == 0) {
            pthread_mutex_unlock(&iam->user_db_lock);
            return &iam->users[i];
        }
    }
    pthread_mutex_unlock(&iam->user_db_lock);
    return NULL;
}

// Database Module
static bool module_database_connect_db(const char* conn_str) {
    printf("[Database] Connecting to database with string: %s\n", conn_str);
    // Dummy connection
    get_security_system_instance()->modules.database.db_handle = (void*)1; // Simulate successful connection
    return true;
}
static void module_database_disconnect_db(void) {
    printf("[Database] Disconnecting from database.\n");
    get_security_system_instance()->modules.database.db_handle = NULL;
}
static security_result_t module_database_execute_query(const char* query) {
    printf("[Database] Executing query: %s\n", query);
    // Dummy execution
    return SECURITY_SUCCESS;
}
static security_result_t module_database_store_data(const char* table, const void* data, size_t data_size) {
    printf("[Database] Storing %zu bytes in table '%s'.\n", data_size, table);
    return SECURITY_SUCCESS;
}
static void* module_database_retrieve_data(const char* table, const char* criteria, size_t* data_size) {
    printf("[Database] Retrieving data from table '%s' with criteria '%s'.\n", table, criteria);
    if (data_size) *data_size = 0;
    return NULL; // Dummy: no data retrieved
}

// --- Central Security System Operations ---

static void central_system_initialize(void) {
    castle_security_system_t* sys = get_security_system_instance();
    if (atomic_load(&sys->state.initialized)) {
        printf("Castle Security System: Already initialized.\n");
        return;
    }

    pthread_mutex_lock(&sys->state.init_lock);
    if (atomic_load(&sys->state.initialized)) { // Double-check lock
        pthread_mutex_unlock(&sys->state.init_lock);
        return;
    }

    printf("Castle Security System: Initializing...\n");

    // --- NEW FEATURE: Crash Resistance Configuration Initialization ---
    atomic_store(&sys->crash_config.auto_reboot, true);
    sys->crash_config.backup_interval_s = 60; // 60 seconds
    atomic_store(&sys->crash_config.quantum_backup_enabled, true);
    atomic_store(&sys->crash_config.neighbor_sync_enabled, true);
    printf("Crash Resistance Config: Auto-reboot=%s, Backup Interval=%us, Quantum Backup=%s, Neighbor Sync=%s\n",
           atomic_load(&sys->crash_config.auto_reboot) ? "yes" : "no",
           sys->crash_config.backup_interval_s,
           atomic_load(&sys->crash_config.quantum_backup_enabled) ? "enabled" : "disabled",
           atomic_load(&sys->crash_config.neighbor_sync_enabled) ? "enabled" : "disabled");


    // Initialize core components
    if (memory_pool_init(&sys->mem_pool, POOL_BLOCK_SIZE, 1024) != SECURITY_SUCCESS) {
        fprintf(stderr, "Failed to initialize memory pool.\n");
        pthread_mutex_unlock(&sys->state.init_lock);
        return;
    }

    // Initialize Event Stream for threading
    sys->event_stream.capacity = 128; // For historical log
    sys->event_stream.entries = (event_stream_entry_t*)malloc(sys->event_stream.capacity * sizeof(event_stream_entry_t));
    if (!sys->event_stream.entries) {
        fprintf(stderr, "Failed to allocate event stream historical log memory.\n");
        memory_pool_destroy(&sys->mem_pool);
        pthread_mutex_unlock(&sys->state.init_lock);
        return;
    }
    sys->event_stream.count = 0;
    pthread_mutex_init(&sys->event_stream.lock, NULL); // For historical log access

    sys->event_stream.head = NULL;
    sys->event_stream.tail = NULL;
    pthread_mutex_init(&sys->event_stream.queue_lock, NULL);
    pthread_cond_init(&sys->event_stream.queue_cond, NULL);
    atomic_store(&sys->event_stream.processing_active, true);
    if (pthread_create(&sys->event_stream.processing_thread, NULL, event_processing_thread_func, sys) != 0) {
        fprintf(stderr, "Failed to create event processing thread.\n");
        atomic_store(&sys->event_stream.processing_active, false);
        // Cleanup other resources
        memory_pool_destroy(&sys->mem_pool);
        free(sys->event_stream.entries);
        pthread_mutex_destroy(&sys->event_stream.lock);
        pthread_mutex_destroy(&sys->event_stream.queue_lock);
        pthread_cond_destroy(&sys->event_stream.queue_cond);
        pthread_mutex_unlock(&sys->state.init_lock);
        return;
    }
    sys->event_stream.subscribe = event_stream_subscribe;
    sys->event_stream.publish = event_stream_publish;


    // Initialize modules
    atomic_store(&sys->modules.messenger.active, true);
    sys->modules.messenger.send_alert = module_messenger_send_alert;
    sys->modules.messenger.notify = module_messenger_notify;
    sys->modules.messenger.broadcast = module_messenger_broadcast;
    sys->modules.messenger.connect_mqtt_tls = module_messenger_connect_mqtt_tls;
    sys->modules.messenger.send_secure_message = module_messenger_send_secure_message;
    sys->modules.messenger.sync_with_neighbors = module_messenger_sync_with_neighbors; // NEW
    atomic_store(&sys->modules.messenger.neighbor_sync_enabled, atomic_load(&sys->crash_config.neighbor_sync_enabled)); // NEW
    atomic_store(&sys->modules.messenger.message_count, 0);
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.internal_monitor.active, true);
    sys->modules.internal_monitor.health_check = module_internal_monitor_health_check;
    sys->modules.internal_monitor.integrity_verification = module_internal_monitor_integrity_verification;
    sys->modules.internal_monitor.dependency_check = module_internal_monitor_dependency_check;
    // Internal module protection
    sys->modules.internal_monitor.self_integrity_check = internal_monitor_self_integrity_check;
    sys->modules.internal_monitor.module_tamper_detection = internal_monitor_module_tamper_detection;
    // Internal Monitor Thread
    pthread_mutex_init(&sys->modules.internal_monitor.thread_lock, NULL);
    pthread_cond_init(&sys->modules.internal_monitor.thread_cond, NULL);
    atomic_store(&sys->modules.internal_monitor.thread_running, true);
    atomic_store(&sys->modules.internal_monitor.trigger_integrity_check, false);
    if (pthread_create(&sys->modules.internal_monitor.monitor_thread, NULL, internal_monitor_thread_func, &sys->modules.internal_monitor) != 0) {
        fprintf(stderr, "Failed to create internal monitor thread.\n");
        atomic_store(&sys->modules.internal_monitor.thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.recovery.active, true);
    sys->modules.recovery.module_recovery = module_recovery_module_recovery;
    sys->modules.recovery.system_rollback = module_recovery_system_rollback;
    sys->modules.recovery.state_restoration = module_recovery_state_restoration;
    sys->modules.recovery.create_snapshot = module_recovery_create_snapshot;
    sys->modules.recovery.restore_from_snapshot = module_recovery_restore_from_snapshot;
    sys->modules.recovery.manage_vulnerabilities = module_recovery_manage_vulnerabilities;
    sys->modules.recovery.apply_patches = module_recovery_apply_patches;
    atomic_store(&sys->modules.recovery.recovery_count, 0);
    // NEW: Recovery Backup Thread
    sys->modules.recovery.backup_interval_seconds = sys->crash_config.backup_interval_s;
    sys->modules.recovery.last_backup_time = time(NULL);
    pthread_mutex_init(&sys->modules.recovery.backup_thread_lock, NULL);
    pthread_cond_init(&sys->modules.recovery.backup_thread_cond, NULL);
    atomic_store(&sys->modules.recovery.backup_thread_running, true);
    if (pthread_create(&sys->modules.recovery.backup_thread, NULL, recovery_backup_thread_func, &sys->modules.recovery) != 0) {
        fprintf(stderr, "Failed to create recovery backup thread.\n");
        atomic_store(&sys->modules.recovery.backup_thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.system_protector.active, true);
    sys->modules.system_protector.scan = module_system_protector_scan;
    sys->modules.system_protector.quarantine = module_system_protector_quarantine;
    sys->modules.system_protector.analysis = module_system_protector_analysis;
    // System Protector Thread
    pthread_mutex_init(&sys->modules.system_protector.thread_lock, NULL);
    pthread_cond_init(&sys->modules.system_protector.thread_cond, NULL);
    atomic_store(&sys->modules.system_protector.thread_running, true);
    atomic_store(&sys->modules.system_protector.trigger_scan, false);
    if (pthread_create(&sys->modules.system_protector.protector_thread, NULL, system_protector_thread_func, &sys->modules.system_protector) != 0) {
        fprintf(stderr, "Failed to create system protector thread.\n");
        atomic_store(&sys->modules.system_protector.thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.firewall_storage.active, true);
    atomic_store(&sys->modules.firewall_storage.rule_count, 0);
    pthread_rwlock_init(&sys->modules.firewall_storage.list_lock, NULL);
    security_list_init(&sys->modules.firewall_storage.blacklist, 16);
    security_list_init(&sys->modules.firewall_storage.whitelist, 16);
    security_list_init(&sys->modules.firewall_storage.suspicious_list, 16);
    sys->modules.firewall_storage.add = firewall_storage_add;
    sys->modules.firewall_storage.remove = firewall_storage_remove;
    sys->modules.firewall_storage.update = firewall_storage_update;
    sys->modules.firewall_storage.check = security_list_check; // Use the generic check
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.inspection_unit.active, true);
    sys->modules.inspection_unit.rule_analysis = module_inspection_unit_rule_analysis;
    sys->modules.inspection_unit.security_enforcement = module_inspection_unit_security_enforcement;
    sys->modules.inspection_unit.policy_optimization = module_inspection_unit_policy_optimization;
    sys->modules.inspection_unit.reporting = module_inspection_unit_reporting;
    atomic_store(&sys->modules.inspection_unit.inspected_requests, 0);
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.kernel_bridge.active, true);
    pthread_mutex_init(&sys->modules.kernel_bridge.sync_lock, NULL);
    sys->modules.kernel_bridge.sync = module_kernel_bridge_sync;
    sys->modules.kernel_bridge.alert = module_kernel_bridge_alert;
    sys->modules.kernel_bridge.command_handler = module_kernel_bridge_command_handler;
    sys->modules.kernel_bridge.secure_ipc_send = module_kernel_bridge_secure_ipc_send;
    sys->modules.kernel_bridge.validate_ipc_message = module_kernel_bridge_validate_ipc_message;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.castle_journal.active, true);
    atomic_store(&sys->modules.castle_journal.log_entries, 0);
    pthread_mutex_init(&sys->modules.castle_journal.log_lock, NULL);
    sys->modules.castle_journal.record = module_castle_journal_record;
    sys->modules.castle_journal.retrieve = module_castle_journal_retrieve;
    sys->modules.castle_journal.analyze = module_castle_journal_analyze;
    sys->modules.castle_journal.compress = module_castle_journal_compress;
    sys->modules.castle_journal.integrate_siem = module_castle_journal_integrate_siem;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.signature_verification.initialized, true); // Placeholder init
    sys->modules.signature_verification.verify_post_quantum_signature = module_signature_verification_verify_post_quantum_signature;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.sandbox.enabled, true);
    atomic_store(&sys->modules.sandbox.sandbox_count, 0);
    pthread_rwlock_init(&sys->modules.sandbox.policy_lock, NULL);
    sys->modules.sandbox.create = module_sandbox_create;
    sys->modules.sandbox.destroy = module_sandbox_destroy;
    sys->modules.sandbox.execute_in_sandbox = sandbox_execute_in_sandbox;
    sys->modules.sandbox.update_policy = module_sandbox_update_policy;
    sys->modules.sandbox.monitor_activity = module_sandbox_monitor_activity;
    // Initialize isolation policy defaults
    sys->modules.sandbox.isolation_policy.isolated_uid = 65534; // nobody
    sys->modules.sandbox.isolation_policy.isolated_gid = 65534; // nogroup
    strncpy(sys->modules.sandbox.isolation_policy.chroot_path, "/var/sandbox", PATH_MAX - 1);
    sys->modules.sandbox.isolation_policy.chroot_path[PATH_MAX - 1] = '\0';
    sys->modules.sandbox.isolation_policy.allowed_syscalls_count = 0;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.firewall.enabled, true);
    security_list_init(&sys->modules.firewall.rules, 32); // Firewall uses rules from storage
    sys->modules.firewall.epoll_fd = epoll_create1(0); // Create epoll instance
    if (sys->modules.firewall.epoll_fd == -1) {
        fprintf(stderr, "Firewall: Failed to create epoll instance: %s\n", strerror(errno));
        // Handle error, potentially return failure or disable module
    } else {
        sys->modules.firewall.events = (struct epoll_event*)malloc(10 * sizeof(struct epoll_event)); // Example size
        if (!sys->modules.firewall.events) {
            fprintf(stderr, "Firewall: Failed to allocate epoll events memory.\n");
            close(sys->modules.firewall.epoll_fd);
            sys->modules.firewall.epoll_fd = -1;
        }
    }
    pthread_mutex_init(&sys->modules.firewall.sk_buff_lock, NULL); // Initialize sk_buff mutex
    sys->modules.firewall.process_packet = module_firewall_process_packet;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.castle_wall.active, true);
    atomic_store(&sys->modules.castle_wall.unauthorized_attempts, 0);
    pthread_rwlock_init(&sys->modules.castle_wall.access_lock, NULL);
    sys->modules.castle_wall.access_monitor = module_castle_wall_access_monitor;
    sys->modules.castle_wall.intrusion_prevention = module_castle_wall_intrusion_prevention;
    sys->modules.castle_wall.threat_assessment = module_castle_wall_threat_assessment;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.watch_tower.active, true);
    atomic_store(&sys->modules.watch_tower.scan_frequency, 60); // Default to 60 scans/min
    sys->modules.watch_tower.threat_detection = module_watch_tower_threat_detection;
    sys->modules.watch_tower.alert_handling = module_watch_tower_alert_handling;
    sys->modules.watch_tower.anomaly_detection = module_watch_tower_anomaly_detection;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.patrol.active, true);
    atomic_store(&sys->modules.patrol.monitored_packets, 0);
    sys->modules.patrol.data_scan = module_patrol_data_scan;
    sys->modules.patrol.suspicious_activity_handler = module_patrol_suspicious_activity_handler;
    sys->modules.patrol.log_activity = module_patrol_log_activity;
    // Lateral Movement Detection
    sys->modules.patrol.detect_lateral_movement = patrol_detect_lateral_movement;
    sys->modules.patrol.respond_lateral_movement = patrol_respond_lateral_movement;
    // For training and tuning Lateral Movement Detection
    atomic_store(&sys->modules.patrol.training_data_processed, 0);
    sys->modules.patrol.tuning_level = 0; // Initial tuning level
    sys->modules.patrol.train_detection_model = patrol_train_detection_model;
    sys->modules.patrol.fine_tune_detection_parameters = patrol_fine_tune_detection_parameters;
    sys->modules.patrol.set_workload_level = patrol_set_workload_level; // NEW
    atomic_store(&sys->modules.patrol.workload_level, 1); // Default to low workload // NEW
    // Patrol Thread
    pthread_mutex_init(&sys->modules.patrol.thread_lock, NULL);
    pthread_cond_init(&sys->modules.patrol.thread_cond, NULL);
    atomic_store(&sys->modules.patrol.thread_running, true);
    atomic_store(&sys->modules.patrol.trigger_detection, false);
    if (pthread_create(&sys->modules.patrol.patrol_thread, NULL, patrol_thread_func, &sys->modules.patrol) != 0) {
        fprintf(stderr, "Failed to create patrol thread.\n");
        atomic_store(&sys->modules.patrol.thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.guardian.active, true);
    atomic_store(&sys->modules.guardian.protected_files, 0);
    sys->modules.guardian.encrypt_data = module_guardian_encrypt_data;
    sys->modules.guardian.decrypt_data = module_guardian_decrypt_data;
    sys->modules.guardian.access_control = module_guardian_access_control;
    sys->modules.guardian.load_key_from_tpm = module_guardian_load_key_from_tpm;
    sys->modules.guardian.generate_key_in_hsm = module_guardian_generate_key_in_hsm;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.security_unit.active, true);
    atomic_store(&sys->modules.security_unit.incidents_resolved, 0);
    sys->modules.security_unit.attack_mitigation = module_security_unit_attack_mitigation;
    sys->modules.security_unit.resource_protection = module_security_unit_resource_protection;
    sys->modules.security_unit.emergency_response = module_security_unit_emergency_response;
    sys->modules.security_unit.automate_response = module_security_unit_automate_response;
    sys->modules.security_unit.orchestrate_incident_response = module_security_unit_orchestrate_incident_response;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.witch.enabled, true);
    atomic_store(&sys->modules.witch.managed_devices, 0);
    pthread_mutex_init(&sys->modules.witch.network_lock, NULL);
    sys->modules.witch.device_registration = module_witch_device_registration;
    sys->modules.witch.traffic_monitoring = module_witch_traffic_monitoring;
    sys->modules.witch.policy_enforcement = module_witch_policy_enforcement;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.arcane_scan.enabled, true);
    atomic_store(&sys->modules.arcane_scan.verification_attempts, 0);
    sys->modules.arcane_scan.verify_with_token = arcane_scan_verify_with_token;
    sys->modules.arcane_scan.biometric_authentication = arcane_scan_biometric_authentication;
    sys->modules.arcane_scan.location_based_verification = arcane_scan_location_based_verification;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.quantum_shield.active, true);
    atomic_store(&sys->modules.quantum_shield.quantum_protection_cycles, 0);
    sys->modules.quantum_shield.initialize_quantum_defense = quantum_initialize_quantum_defense;
    sys->modules.quantum_shield.generate_keys = quantum_generate_keys;
    sys->modules.quantum_shield.encrypt_data = quantum_encrypt_data;
    sys->modules.quantum_shield.decrypt_data = quantum_decrypt_data;
    sys->modules.quantum_shield.sign_data = quantum_sign_data;
    sys->modules.quantum_shield.verify_signature = quantum_verify_signature;
    // Quantum-based detection and cache protection
    sys->modules.quantum_shield.detect_quantum_anomalies = quantum_detect_quantum_anomalies;
    sys->modules.quantum_shield.protect_cache = quantum_protect_cache;
    quantum_initialize_quantum_defense(&sys->modules.quantum_shield.ctx); // Initialize quantum context
    // Quantum Shield Thread
    pthread_mutex_init(&sys->modules.quantum_shield.thread_lock, NULL);
    pthread_cond_init(&sys->modules.quantum_shield.thread_cond, NULL);
    atomic_store(&sys->modules.quantum_shield.thread_running, true);
    atomic_store(&sys->modules.quantum_shield.trigger_anomaly_detection, false);
    atomic_store(&sys->modules.quantum_shield.trigger_cache_protection, false);
    if (pthread_create(&sys->modules.quantum_shield.quantum_thread, NULL, quantum_shield_thread_func, &sys->modules.quantum_shield) != 0) {
        fprintf(stderr, "Failed to create quantum shield thread.\n");
        atomic_store(&sys->modules.quantum_shield.thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.cipher_sentinel.active, true);
    atomic_store(&sys->modules.cipher_sentinel.encrypted_keys, 0);
    sys->modules.cipher_sentinel.secure_key_generation = module_cipher_sentinel_secure_key_generation;
    sys->modules.cipher_sentinel.real_time_cipher_monitoring = module_cipher_sentinel_real_time_cipher_monitoring;
    sys->modules.cipher_sentinel.decryption_protection = module_cipher_sentinel_decryption_protection;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.shadow_gatekeeper.active, true);
    atomic_store(&sys->modules.shadow_gatekeeper.monitored_packets, 0);
    pthread_mutex_init(&sys->modules.shadow_gatekeeper.gatekeeper_lock, NULL);
    atomic_store(&sys->modules.shadow_gatekeeper.wasm_enabled, false);
    sys->modules.shadow_gatekeeper.wasm_module_handle = NULL;
    sys->modules.shadow_gatekeeper.load_wasm_filter = module_shadow_gatekeeper_load_wasm_filter;
    sys->modules.shadow_gatekeeper.unload_wasm_filter = module_shadow_gatekeeper_unload_wasm_filter;
    sys->modules.shadow_gatekeeper.process_with_wasm = module_shadow_gatekeeper_process_with_wasm;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.secure_boot.verified, false); // Will be verified on boot
    atomic_store(&sys->modules.secure_boot.boot_attempts, 0);
    pthread_mutex_init(&sys->modules.secure_boot.verification_lock, NULL);
    sys->modules.secure_boot.verify_hardware = secure_boot_verify_hardware;
    sys->modules.secure_boot.verify_firmware = secure_boot_verify_firmware;
    sys->modules.secure_boot.verify_kernel = secure_boot_verify_kernel;
    sys->modules.secure_boot.verify_boot_chain = secure_boot_verify_boot_chain;
    sys->modules.secure_boot.recovery_boot = module_secure_boot_recovery_boot;
    // Example hashes
    memset(sys->modules.secure_boot.known_good_hashes.hardware_hash, 0x01, SHA256_DIGEST_LENGTH);
    memset(sys->modules.secure_boot.known_good_hashes.firmware_hash, 0x02, SHA256_DIGEST_LENGTH);
    memset(sys->modules.secure_boot.known_good_hashes.kernel_hash, 0x03, SHA256_DIGEST_LENGTH);
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.phantom_hand.active, true);
    atomic_store(&sys->modules.phantom_hand.offloaded_tasks, 0);
    sys->modules.phantom_hand.configure_fpga = module_phantom_hand_configure_fpga;
    sys->modules.phantom_hand.program_asic = module_phantom_hand_program_asic;
    sys->modules.phantom_hand.offload_processing = module_phantom_hand_offload_processing;
    sys->modules.phantom_hand.dynamic_schedule_tasks = module_phantom_hand_dynamic_schedule_tasks;
    sys->modules.phantom_hand.optimize_power_consumption = module_phantom_hand_optimize_power_consumption;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.wisdom_flow.enabled, true);
    atomic_store(&sys->modules.wisdom_flow.backported_features, 0);
    sys->modules.wisdom_flow.apply_backport = module_wisdom_flow_apply_backport;
    sys->modules.wisdom_flow.verify_compatibility = module_wisdom_flow_verify_compatibility;
    sys->modules.wisdom_flow.rollback_changes = module_wisdom_flow_rollback_changes;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.grumpy_frame.active, true);
    atomic_store(&sys->modules.grumpy_frame.isolated_processes, 0);
    sys->modules.grumpy_frame.create_hardware_sandbox = module_grumpy_frame_create_hardware_sandbox;
    sys->modules.grumpy_frame.isolate_process = module_grumpy_frame_isolate_process;
    sys->modules.grumpy_frame.monitor_sandbox = module_grumpy_frame_monitor_sandbox;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.fast_barrier.enabled, true);
    atomic_store(&sys->modules.fast_barrier.processed_packets, 0);
    sys->modules.fast_barrier.load_ebpf_program = module_fast_barrier_load_ebpf_program;
    sys->modules.fast_barrier.configure_xdp_filter = module_fast_barrier_configure_xdp_filter;
    sys->modules.fast_barrier.optimize_packet_processing = module_fast_barrier_optimize_packet_processing;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.lazy_zoom.active, true);
    atomic_store(&sys->modules.lazy_zoom.balanced_connections, 0);
    sys->modules.lazy_zoom.distribute_traffic = module_lazy_zoom_distribute_traffic;
    sys->modules.lazy_zoom.add_server_node = module_lazy_zoom_add_server_node;
    sys->modules.lazy_zoom.remove_server_node = module_lazy_zoom_remove_server_node;
    sys->modules.lazy_zoom.apply_load_balancing = module_lazy_zoom_apply_load_balancing;
    sys->modules.lazy_zoom.self_tune_system = module_lazy_zoom_self_tune_system;
    atomic_fetch_add(&sys->state.active_modules, 1);

    atomic_store(&sys->modules.granite.enabled, true);
    atomic_store(&sys->modules.granite.secured_enclaves, 0);
    sys->modules.granite.initialize_sgx = module_granite_initialize_sgx;
    sys->modules.granite.setup_sev = module_granite_setup_sev;
    sys->modules.granite.create_secure_enclave = module_granite_create_secure_enclave;
    atomic_fetch_add(&sys->state.active_modules, 1);

    // Initialize Spectre and Timing Attack Defense Module
    atomic_store(&sys->modules.spectre_timing_defense.active, true);
    atomic_store(&sys->modules.spectre_timing_defense.mitigated_attacks_count, 0);
    pthread_mutex_init(&sys->modules.spectre_timing_defense.defense_lock, NULL);
    pthread_cond_init(&sys->modules.spectre_timing_defense.thread_cond, NULL);
    atomic_store(&sys->modules.spectre_timing_defense.thread_running, true);
    atomic_store(&sys->modules.spectre_timing_defense.trigger_detection, false);
    sys->modules.spectre_timing_defense.enable_mitigations = spectre_timing_enable_mitigations;
    sys->modules.spectre_timing_defense.disable_mitigations = spectre_timing_disable_mitigations;
    sys->modules.spectre_timing_defense.detect_spectre_attack = spectre_timing_detect_spectre_attack;
    sys->modules.spectre_timing_defense.detect_timing_attack = spectre_timing_detect_timing_attack;
    sys->modules.spectre_timing_defense.apply_speculative_execution_hardening = spectre_timing_apply_speculative_execution_hardening;
    sys->modules.spectre_timing_defense.apply_timing_noise = spectre_timing_apply_timing_noise;
    if (pthread_create(&sys->modules.spectre_timing_defense.defense_thread, NULL, spectre_timing_defense_thread_func, &sys->modules.spectre_timing_defense) != 0) {
        fprintf(stderr, "Failed to create spectre/timing defense thread.\n");
        atomic_store(&sys->modules.spectre_timing_defense.thread_running, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);

    // Fairshare Warden initialization
    atomic_store(&sys->modules.fairshare_warden.active, true);
    atomic_store(&sys->modules.fairshare_warden.managed_groups, 0);
    pthread_rwlock_init(&sys->modules.fairshare_warden.policy_lock, NULL);
    sys->modules.fairshare_warden.monitor_resource_usage = module_fairshare_warden_monitor_resource_usage;
    sys->modules.fairshare_warden.enforce_fairshare_rules = module_fairshare_warden_enforce_fairshare_rules;
    sys->modules.fairshare_warden.adjust_resource_allocation = module_fairshare_warden_adjust_resource_allocation;
    sys->modules.fairshare_warden.detect_violations = module_fairshare_warden_detect_violations;
    sys->modules.fairshare_warden.report_usage_statistics = module_fairshare_warden_report_usage_statistics;
    sys->modules.fairshare_warden.update_gui_display = module_fairshare_warden_update_gui_display;
    sys->modules.fairshare_warden.enforce_qos = module_fairshare_warden_enforce_qos;
    sys->modules.fairshare_warden.get_realtime_metrics = module_fairshare_warden_get_realtime_metrics;
    sys->modules.fairshare_warden.set_resource_quota = fairshare_warden_set_resource_quota; // NEW
    sys->modules.fairshare_warden.policy_count = 0;
    sys->modules.fairshare_warden.management_window = NULL; // GUI window handle
    atomic_fetch_add(&sys->state.active_modules, 1);

    // IAM Module Initialization
    atomic_store(&sys->modules.iam.active, true);
    atomic_store(&sys->modules.iam.authenticated_users, 0);
    sys->modules.iam.user_count = 0; // Initialize user count
    pthread_mutex_init(&sys->modules.iam.user_db_lock, NULL); // NEW
    sys->modules.iam.authenticate_user = module_iam_authenticate_user;
    sys->modules.iam.authorize_action = module_iam_authorize_action;
    sys->modules.iam.add_user = module_iam_add_user;
    sys->modules.iam.remove_user = module_iam_remove_user;
    sys->modules.iam.get_user_by_uid = module_iam_get_user_by_uid; // NEW
    sys->modules.iam.get_user_by_username = module_iam_get_user_by_username; // NEW
    // Add some default/important users
    sys->modules.iam.add_user("admin", "securepass", "admin", CASTLE_ADMIN_UID);
    sys->modules.iam.add_user("auditor", "auditpass", "auditor", CASTLE_AUDITOR_UID);
    sys->modules.iam.add_user("guest", "guestpass", "guest", 0); // Auto-assigned UID
    atomic_fetch_add(&sys->state.active_modules, 1);

    // Database Module Initialization
    atomic_store(&sys->modules.database.active, true);
    strncpy(sys->modules.database.connection_string, "host=localhost;port=5432;dbname=security_db", sizeof(sys->modules.database.connection_string) - 1);
    sys->modules.database.connection_string[sizeof(sys->modules.database.connection_string) - 1] = '\0';
    sys->modules.database.db_handle = NULL;
    sys->modules.database.connect_db = module_database_connect_db;
    sys->modules.database.disconnect_db = module_database_disconnect_db;
    sys->modules.database.execute_query = module_database_execute_query;
    sys->modules.database.store_data = module_database_store_data;
    sys->modules.database.retrieve_data = module_database_retrieve_data;
    if (!sys->modules.database.connect_db(sys->modules.database.connection_string)) {
        fprintf(stderr, "Failed to connect to independent database.\n");
        atomic_store(&sys->modules.database.active, false);
    }
    atomic_fetch_add(&sys->state.active_modules, 1);


    // Assign central system operations
    sys->initialize = central_system_initialize; // Self-reference for consistency
    sys->shutdown = central_system_shutdown;
    sys->emergency_lockdown = central_system_emergency_lockdown;
    sys->update_security_policy = central_system_update_security_policy;
    sys->open_fairshare_manager = central_system_open_fairshare_manager;
    sys->close_fairshare_manager = central_system_close_fairshare_manager;
    sys->update_resource_displays = central_system_update_resource_displays;
    sys->handle_kernel_error = central_system_handle_kernel_error;
    sys->load_module = central_system_load_module;
    sys->unload_module = central_system_unload_module;

    // Initialize GUI
    if (init_security_gui(sys) != SECURITY_SUCCESS) {
        fprintf(stderr, "Failed to initialize security GUI.\n");
        // Clean up previously initialized non-GUI components if GUI is critical
        memory_pool_destroy(&sys->mem_pool);
        event_stream_cleanup(&sys->event_stream); // Use dedicated cleanup
        pthread_mutex_unlock(&sys->state.init_lock);
        return;
    }

    atomic_store(&sys->state.initialized, true);
    pthread_mutex_unlock(&sys->state.init_lock);
    printf("Castle Security System: Initialization complete. Active modules: %u\n", atomic_load(&sys->state.active_modules));
}

static void central_system_shutdown(void) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!atomic_load(&sys->state.initialized)) {
        printf("Castle Security System: Not initialized, nothing to shut down.\n");
        return;
    }

    printf("Castle Security System: Shutting down...\n");

    // Shutdown GUI first
    shutdown_security_gui(sys);

    // Signal and join all dedicated threads
    event_stream_cleanup(&sys->event_stream); // Use dedicated cleanup

    atomic_store(&sys->modules.internal_monitor.thread_running, false);
    pthread_mutex_lock(&sys->modules.internal_monitor.thread_lock);
    pthread_cond_signal(&sys->modules.internal_monitor.thread_cond);
    pthread_mutex_unlock(&sys->modules.internal_monitor.thread_lock);
    pthread_join(sys->modules.internal_monitor.monitor_thread, NULL);

    atomic_store(&sys->modules.system_protector.thread_running, false);
    pthread_mutex_lock(&sys->modules.system_protector.thread_lock);
    pthread_cond_signal(&sys->modules.system_protector.thread_cond);
    pthread_mutex_unlock(&sys->modules.system_protector.thread_lock);
    pthread_join(sys->modules.system_protector.protector_thread, NULL);

    atomic_store(&sys->modules.patrol.thread_running, false);
    pthread_mutex_lock(&sys->modules.patrol.thread_lock);
    pthread_cond_signal(&sys->modules.patrol.thread_cond);
    pthread_mutex_unlock(&sys->modules.patrol.thread_lock);
    pthread_join(sys->modules.patrol.patrol_thread, NULL);

    atomic_store(&sys->modules.quantum_shield.thread_running, false);
    pthread_mutex_lock(&sys->modules.quantum_shield.thread_lock);
    pthread_cond_signal(&sys->modules.quantum_shield.thread_cond);
    pthread_mutex_unlock(&sys->modules.quantum_shield.thread_lock);
    pthread_join(sys->modules.quantum_shield.quantum_thread, NULL);

    atomic_store(&sys->modules.spectre_timing_defense.thread_running, false);
    pthread_mutex_lock(&sys->modules.spectre_timing_defense.thread_lock);
    pthread_cond_signal(&sys->modules.spectre_timing_defense.thread_cond);
    pthread_mutex_unlock(&sys->modules.spectre_timing_defense.thread_lock);
    pthread_join(sys->modules.spectre_timing_defense.defense_thread, NULL);

    // NEW: Stop Recovery Backup Thread
    atomic_store(&sys->modules.recovery.backup_thread_running, false);
    pthread_mutex_lock(&sys->modules.recovery.backup_thread_lock);
    pthread_cond_signal(&sys->modules.recovery.backup_thread_cond);
    pthread_mutex_unlock(&sys->modules.recovery.backup_thread_lock);
    pthread_join(sys->modules.recovery.backup_thread, NULL);


    // Destroy modules and their resources
    atomic_store(&sys->modules.messenger.active, false);

    // Internal Monitor cleanup
    atomic_store(&sys->modules.internal_monitor.active, false);
    pthread_mutex_destroy(&sys->modules.internal_monitor.thread_lock);
    pthread_cond_destroy(&sys->modules.internal_monitor.thread_cond);

    atomic_store(&sys->modules.recovery.active, false);
    pthread_mutex_destroy(&sys->modules.recovery.backup_thread_lock); // NEW
    pthread_cond_destroy(&sys->modules.recovery.backup_thread_cond); // NEW

    atomic_store(&sys->modules.system_protector.active, false);
    pthread_mutex_destroy(&sys->modules.system_protector.thread_lock);
    pthread_cond_destroy(&sys->modules.system_protector.thread_cond);

    pthread_rwlock_destroy(&sys->modules.firewall_storage.list_lock);
    security_list_cleanup(&sys->modules.firewall_storage.blacklist); // Use dedicated cleanup
    security_list_cleanup(&sys->modules.firewall_storage.whitelist); // Use dedicated cleanup
    security_list_cleanup(&sys->modules.firewall_storage.suspicious_list); // Use dedicated cleanup
    atomic_store(&sys->modules.firewall_storage.active, false);

    atomic_store(&sys->modules.inspection_unit.active, false);
    pthread_mutex_destroy(&sys->modules.kernel_bridge.sync_lock);
    atomic_store(&sys->modules.kernel_bridge.active, false);
    pthread_mutex_destroy(&sys->modules.castle_journal.log_lock);
    atomic_store(&sys->modules.castle_journal.active, false);
    atomic_store(&sys->modules.signature_verification.initialized, false);

    pthread_rwlock_destroy(&sys->modules.sandbox.policy_lock);
    atomic_store(&sys->modules.sandbox.enabled, false);

    if (sys->modules.firewall.epoll_fd != -1) {
        close(sys->modules.firewall.epoll_fd);
        sys->modules.firewall.epoll_fd = -1;
    }
    if (sys->modules.firewall.events) {
        free(sys->modules.firewall.events);
        sys->modules.firewall.events = NULL;
    }
    security_list_cleanup(&sys->modules.firewall.rules); // Use dedicated cleanup
    pthread_mutex_destroy(&sys->modules.firewall.sk_buff_lock); // Destroy sk_buff mutex
    atomic_store(&sys->modules.firewall.enabled, false);

    pthread_rwlock_destroy(&sys->modules.castle_wall.access_lock);
    atomic_store(&sys->modules.castle_wall.active, false);
    atomic_store(&sys->modules.watch_tower.active, false);
    atomic_store(&sys->modules.patrol.active, false);
    pthread_mutex_destroy(&sys->modules.patrol.thread_lock);
    pthread_cond_destroy(&sys->modules.patrol.thread_cond);

    atomic_store(&sys->modules.guardian.active, false);
    atomic_store(&sys->modules.security_unit.active, false);
    pthread_mutex_destroy(&sys->modules.witch.network_lock);
    atomic_store(&sys->modules.witch.enabled, false);
    atomic_store(&sys->modules.arcane_scan.enabled, false);

    // Quantum Shield cleanup
    pthread_rwlock_wrlock(&sys->modules.quantum_shield.ctx.key_lock);
    if (sys->modules.quantum_shield.ctx.public_key) free(sys->modules.quantum_shield.ctx.public_key);
    if (sys->modules.quantum_shield.ctx.secret_key) free(sys->modules.quantum_shield.ctx.secret_key);
    if (sys->modules.quantum_shield.ctx.kem) OQS_KEM_free(sys->modules.quantum_shield.ctx.kem);
    if (sys->modules.quantum_shield.ctx.sig) OQS_SIG_free(sys->modules.quantum_shield.ctx.sig);
    pthread_rwlock_unlock(&sys->modules.quantum_shield.ctx.key_lock);
    pthread_rwlock_destroy(&sys->modules.quantum_shield.ctx.key_lock);
    atomic_store(&sys->modules.quantum_shield.active, false);
    pthread_mutex_destroy(&sys->modules.quantum_shield.thread_lock);
    pthread_cond_destroy(&sys->modules.quantum_shield.thread_cond);

    atomic_store(&sys->modules.cipher_sentinel.active, false);
    pthread_mutex_destroy(&sys->modules.shadow_gatekeeper.gatekeeper_lock);
    atomic_store(&sys->modules.shadow_gatekeeper.active, false);
    pthread_mutex_destroy(&sys->modules.secure_boot.verification_lock);
    atomic_store(&sys->modules.secure_boot.verified, false);
    atomic_store(&sys->modules.phantom_hand.active, false);
    atomic_store(&sys->modules.wisdom_flow.enabled, false);
    atomic_store(&sys->modules.grumpy_frame.active, false);
    atomic_store(&sys->modules.fast_barrier.enabled, false);
    atomic_store(&sys->modules.lazy_zoom.active, false);
    atomic_store(&sys->modules.granite.enabled, false);

    // Spectre and Timing Attack Defense Module cleanup
    pthread_mutex_destroy(&sys->modules.spectre_timing_defense.defense_lock);
    pthread_cond_destroy(&sys->modules.spectre_timing_defense.thread_cond);
    atomic_store(&sys->modules.spectre_timing_defense.active, false);

    pthread_rwlock_destroy(&sys->modules.fairshare_warden.policy_lock);
    atomic_store(&sys->modules.fairshare_warden.active, false);

    // IAM Module cleanup
    pthread_mutex_destroy(&sys->modules.iam.user_db_lock); // NEW
    atomic_store(&sys->modules.iam.active, false);

    // Database Module cleanup
    if (atomic_load(&sys->modules.database.active)) {
        sys->modules.database.disconnect_db();
    }
    atomic_store(&sys->modules.database.active, false);


    // Destroy core components
    memory_pool_destroy(&sys->mem_pool);

    atomic_store(&sys->state.initialized, false);
    atomic_store(&sys->state.active_modules, 0);
    pthread_mutex_destroy(&sys->state.init_lock); // Destroy the init lock last
    printf("Castle Security System: Shutdown complete.\n");
}

static void central_system_emergency_lockdown(void) {
    printf("Castle Security System: Initiating ADVANCED emergency lockdown! All non-essential services halted, deep threat analysis activated.\n");
    castle_security_system_t* sys = get_security_system_instance();

    // Existing actions:
    atomic_store(&sys->modules.firewall.enabled, true);
    sys->modules.firewall_storage.add("0.0.0.0/0", RULE_IP_BASED, "Emergency Lockdown: Block All");
    atomic_store(&sys->modules.witch.enabled, false); // Disable network access control
    sys->modules.messenger.send_alert(EVENT_SECURITY_BREACH, "Emergency lockdown activated!");

    // --- NEW FEATURE: Auto-reboot for Crash Resistance ---
    if (atomic_load(&sys->crash_config.auto_reboot)) {
        printf("Emergency Lockdown: Auto-reboot is enabled. System will attempt to reboot after critical state stabilization.\n");
        // In a real system, this would trigger a watchdog timer or a systemd/initctl reboot command.
        sys->event_stream.publish(EVENT_CRASH_RECOVERY_INITIATED, "Auto-reboot triggered by emergency lockdown.");
    }

    // Advanced actions for lockdown - now triggering threaded operations
    // 1. Activate deep scan and analysis on System Protector
    atomic_store(&sys->modules.system_protector.trigger_scan, true);
    pthread_mutex_lock(&sys->modules.system_protector.thread_lock);
    pthread_cond_signal(&sys->modules.system_protector.thread_cond);
    pthread_mutex_unlock(&sys->modules.system_protector.thread_lock);

    // 2. Isolate critical processes using Grumpy Frame (hardware sandboxing)
    sys->modules.grumpy_frame.create_hardware_sandbox();
    sys->modules.grumpy_frame.isolate_process(100); // Example: isolate PID 100
    sys->modules.grumpy_frame.monitor_sandbox();

    // 3. Activate Quantum Shield's anomaly detection and cache protection
    if (atomic_load(&sys->modules.quantum_shield.active)) {
        atomic_store(&sys->modules.quantum_shield.trigger_anomaly_detection, true);
        atomic_store(&sys->modules.quantum_shield.trigger_cache_protection, true);
        pthread_mutex_lock(&sys->modules.quantum_shield.thread_lock);
        pthread_cond_signal(&sys->modules.quantum_shield.thread_cond);
        pthread_mutex_unlock(&sys->modules.quantum_shield.thread_lock);
    }

    // 4. Enable all Spectre/Timing attack mitigations and trigger detection
    if (atomic_load(&sys->modules.spectre_timing_defense.active)) {
        sys->modules.spectre_timing_defense.enable_mitigations();
        sys->modules.spectre_timing_defense.apply_speculative_execution_hardening();
        sys->modules.spectre_timing_defense.apply_timing_noise();
        atomic_store(&sys->modules.spectre_timing_defense.trigger_detection, true);
        pthread_mutex_lock(&sys->modules.spectre_timing_defense.thread_lock);
        pthread_cond_signal(&sys->modules.spectre_timing_defense.thread_cond);
        pthread_mutex_unlock(&sys->modules.spectre_timing_defense.thread_lock);
    }

    // 5. Trigger lateral movement response and detection in Patrol
    sys->modules.patrol.respond_lateral_movement();
    atomic_store(&sys->modules.patrol.trigger_detection, true);
    pthread_mutex_lock(&sys->modules.patrol.thread_lock);
    pthread_cond_signal(&sys->modules.patrol.thread_cond);
    pthread_mutex_unlock(&sys->modules.patrol.thread_lock);

    // 6. Perform self-integrity checks and module tamper detection
    atomic_store(&sys->modules.internal_monitor.trigger_integrity_check, true);
    pthread_mutex_lock(&sys->modules.internal_monitor.thread_lock);
    pthread_cond_signal(&sys->modules.internal_monitor.thread_cond);
    pthread_mutex_unlock(&sys->modules.internal_monitor.thread_lock);

    // 7. Trigger SOAR automated response
    sys->modules.security_unit.automate_response(EVENT_SECURITY_BREACH);

    // 8. Create a system snapshot for recovery
    sys->modules.recovery.create_snapshot("Emergency_Lockdown_State");

    // 9. NEW: Trigger neighbor synchronization to inform other nodes
    sys->modules.messenger.sync_with_neighbors();

    // Update GUI
    if (sys->gui_context.security_status_label) {
        set_label_text(sys->gui_context.security_status_label, "System Status: ADVANCED EMERGENCY LOCKDOWN!");
        set_label_text_color(sys->gui_context.security_status_label, 0xFFFF0000); // Red
    }
    if (sys->gui_context.status_bar) {
        set_status_bar_panel_text(sys->gui_context.status_bar, 0, "STATUS: ADVANCED LOCKDOWN", 0xFFFF0000);
    }
    // Show a dialog
    wchar_t title[] = L"CRITICAL EMERGENCY ALERT";
    wchar_t msg[] = L"Castle Security System is now in ADVANCED EMERGENCY LOCKDOWN mode due to a severe, critical threat!";
    show_message_box(sys->gui_context.main_security_window, title, msg, 0); // Assuming 0 is MESSAGE_BOX_ERROR
}

static void central_system_update_security_policy(void) {
    printf("Castle Security System: Updating security policies.\n");
    // This would involve reloading rules, reconfiguring modules, etc.
    castle_security_system_t* sys = get_security_system_instance();
    sys->modules.firewall_storage.add("192.168.1.100", RULE_IP_BASED, "Allow trusted internal host");
    sys->modules.firewall_storage.add("malicious.com", RULE_CONTENT_BASED, "Block known malicious domain");

    // Example of updating Patrol's tuning level and workload
    sys->modules.patrol.fine_tune_detection_parameters(75); // Set to a higher tuning level
    sys->modules.patrol.set_workload_level(3); // Set patrol to high workload // NEW
    // Example of training Patrol with some dummy data (in a real scenario, this would be real data)
    char dummy_training_data[] = "network_log_entry_123_real_data";
    sys->modules.patrol.train_detection_model(dummy_training_data, sizeof(dummy_training_data));

    // Example of applying patches and managing vulnerabilities
    sys->modules.recovery.manage_vulnerabilities();
    sys->modules.recovery.apply_patches();

    // Example of updating IAM policies
    sys->modules.iam.add_user("new_guard", "strong_password", "patrol_role", 0); // Auto-assigned UID

    // Example of setting resource quotas
    sys->modules.fairshare_warden.set_resource_quota("CriticalServices", 0.8, 1024 * 1024 * 512, 1024 * 1024 * 100); // 80% CPU, 512MB Mem, 100MB/s IO
    sys->modules.fairshare_warden.set_resource_quota("GuestUsers", 0.1, 1024 * 1024 * 64, 1024 * 1024 * 10); // 10% CPU, 64MB Mem, 10MB/s IO

    // Update GUI
    if (sys->gui_context.status_bar) {
        set_status_bar_panel_text(sys->gui_context.status_bar, 1, "Policy Updated", 0xFF00FF00); // Green
    }
}

static void central_system_open_fairshare_manager(void) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys->gui_context.fairshare_warden_gui_window_ref) {
        printf("Castle Security System: Opening Fairshare Warden GUI manager.\n");
        sys->gui_context.fairshare_warden_gui_window_ref = create_fairshare_warden_window(sys->gui_context.main_security_window, &sys->modules.fairshare_warden);
        if (sys->gui_context.fairshare_warden_gui_window_ref) {
            // Set it visible, bring to front etc.
            // set_window_visible(sys->gui_context.fairshare_warden_gui_window_ref, true);
            // set_window_focused(sys->gui_context.fairshare_warden_gui_window_ref, true);
        } else {
            fprintf(stderr, "Failed to create Fairshare Warden GUI window.\n");
        }
    } else {
        printf("Castle Security System: Fairshare Warden GUI manager already open.\n");
        // set_window_focused(sys->gui_context.fairshare_warden_gui_window_ref, true);
    }
}

static void central_system_close_fairshare_manager(void) {
    castle_security_system_t* sys = get_security_system_instance();
    if (sys->gui_context.fairshare_warden_gui_window_ref) {
        printf("Castle Security System: Closing Fairshare Warden GUI manager.\n");
        destroy_window(sys->gui_context.fairshare_warden_gui_window_ref);
        sys->gui_context.fairshare_warden_gui_window_ref = NULL;
    } else {
        printf("Castle Security System: Fairshare Warden GUI manager not open.\n");
    }
}

static void central_system_update_resource_displays(void) {
    printf("Castle Security System: Updating resource displays.\n");
    // This would iterate through fairshare groups and update their resource_meter_t values
    if (g_security_system->gui_context.fairshare_warden_gui_window_ref) {
        update_fairshare_display(g_security_system->gui_context.fairshare_warden_gui_window_ref);
    }
}

static sdkk_error_t central_system_handle_kernel_error(sdkk_error_t error) {
    fprintf(stderr, "Castle Security System: Handling kernel error: %d\n", error);
    // Log the error, potentially trigger recovery or alert
    get_security_system_instance()->modules.messenger.send_alert(EVENT_SYSTEM_RESTORED, "Kernel error detected and handled.");
    // Show a GUI alert
    wchar_t title[] = L"Kernel Error";
    char msg_buf[128];
    snprintf(msg_buf, sizeof(msg_buf), "A kernel error occurred: %d. System restored.", error);
    wchar_t wmsg_buf[128];
    mbstowcs(wmsg_buf, msg_buf, sizeof(wmsg_buf));
    show_message_box(get_security_system_instance()->gui_context.main_security_window, title, wmsg_buf, 0); // Assuming 0 is MESSAGE_BOX_INFO
    return error; // Return the error code
}

static sdkk_error_t central_system_load_module(const dro_module_t* module) {
    if (!module) return -1; // SDKK_ERROR_INVALID_ARGS
    printf("Castle Security System: Loading module: %s.\n", module->name);
    // In a real system, this would load a dynamic library/kernel module
    get_security_system_instance()->event_stream.publish(EVENT_MODULE_LOADED, module->name);
    return 0; // SDKK_SUCCESS
}

static sdkk_error_t central_system_unload_module(const dro_module_t* module) {
    if (!module) return -1; // SDKK_ERROR_INVALID_ARGS
    printf("Castle Security System: Unloading module: %s.\n", module->name);
    // In a real system, this would unload a dynamic library/kernel module
    get_security_system_instance()->event_stream.publish(EVENT_MODULE_UNLOADED, module->name);
    return 0; // SDKK_SUCCESS
}

// --- GUI Specific Helper Functions ---

// Implementation for security_event_type_to_str
const char* security_event_type_to_str(security_event_type_t event_type) {
    switch (event_type) {
        case EVENT_FIREWALL_ALERT: return "Firewall Alert";
        case EVENT_INTRUSION_ATTEMPT: return "Intrusion Attempt";
        case EVENT_MALWARE_DETECTED: return "Malware Detected";
        case EVENT_DATA_LEAK_PREVENTED: return "Data Leak Prevented";
        case EVENT_SYSTEM_RESTORED: return "System Restored";
        case EVENT_SECURITY_BREACH: return "Security Breach";
        case EVENT_POLICY_UPDATE: return "Policy Update";
        case EVENT_MODULE_LOADED: return "Module Loaded";
        case EVENT_MODULE_UNLOADED: return "Module Unloaded";
        case EVENT_RESOURCE_VIOLATION: return "Resource Violation";
        case EVENT_QUANTUM_KEY_GEN_FAILED: return "Quantum Key Gen Failed";
        case EVENT_QUANTUM_ENCRYPT_FAILED: return "Quantum Encrypt Failed";
        case EVENT_LATERAL_MOVEMENT_DETECTED: return "Lateral Movement Detected";
        case EVENT_VULNERABILITY_DETECTED: return "Vulnerability Detected";
        case EVENT_PATCH_APPLIED: return "Patch Applied";
        case EVENT_SOAR_RESPONSE_INITIATED: return "SOAR Response Initiated";
        case EVENT_SECURE_MESSAGE_SENT: return "Secure Message Sent";
        case EVENT_DB_ACCESS_DENIED: return "DB Access Denied";
        case EVENT_IAM_AUTH_FAILED: return "IAM Auth Failed";
        case EVENT_RESOURCE_QUOTA_VIOLATION: return "Resource Quota Violation"; // NEW
        case EVENT_CRASH_RECOVERY_INITIATED: return "Crash Recovery Initiated"; // NEW
        case EVENT_NONE:
        case _EVENT_TYPE_COUNT:
        default: return "Unknown Event";
    }
}

// Implementation for format_time
void format_time(time_t timestamp, char* buffer, size_t buffer_size) {
    struct tm *info;
    time_t rawtime = timestamp;
    char temp_buf[64];
    info = localtime(&rawtime);
    strftime(temp_buf, sizeof(temp_buf), "%Y-%m-%d %H:%M:%S", info);
    strncpy(buffer, temp_buf, buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

// --- NEW FEATURE: GUI Input Validation Helper Implementation ---
bool validate_firewall_rule_input(const char* rule_text, const char* type_text) {
    if (!rule_text || strlen(rule_text) == 0) {
        return false; // Rule cannot be empty
    }

    if (strcmp(type_text, "IP_BASED") == 0) {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
        // Check for IPv4 or IPv6
        if (inet_pton(AF_INET, rule_text, &(sa.sin_addr)) != 1 &&
            inet_pton(AF_INET6, rule_text, &(sa6.sin6_addr)) != 1) {
            return false; // Not a valid IP address
        }
    } else if (strcmp(type_text, "PORT_BASED") == 0) {
        for (size_t i = 0; i < strlen(rule_text); i++) {
            if (!isdigit(rule_text[i])) {
                return false; // Not a valid number
            }
        }
        int port = atoi(rule_text);
        if (port <= 0 || port > 65535) {
            return false; // Invalid port range
        }
    } else if (strcmp(type_text, "PROTOCOL_BASED") == 0) {
        // Simple check for common protocols
        if (strcmp(rule_text, "TCP") != 0 && strcmp(rule_text, "UDP") != 0 &&
            strcmp(rule_text, "ICMP") != 0 && strcmp(rule_text, "ANY") != 0) {
            return false; // Not a recognized protocol
        }
    } else if (strcmp(type_text, "CONTENT_BASED") == 0 || strcmp(type_text, "BEHAVIOR_BASED") == 0 ||
               strcmp(type_text, "EBPF_FILTERED") == 0 || strcmp(type_text, "SIGNATURE_BASED") == 0 ||
               strcmp(type_text, "QUANTUM_ENFORCED") == 0) {
        // For these types, any non-empty string might be considered valid for this dummy validation
        if (strlen(rule_text) < 3) return false; // Require at least 3 chars for content/behavior rules
    } else {
        return false; // Unknown rule type
    }
    return true;
}


// --- GUI Initialization and Shutdown ---

security_result_t init_security_gui(castle_security_system_t* sys) {
    printf("Initializing Castle Security GUI...\n");
    security_gui_context_t* gui = &sys->gui_context;

    // 1. Create Main Window
    gui->main_security_window = create_security_management_window(sys);
    if (!gui->main_security_window) {
        fprintf(stderr, "Failed to create main security window.\n");
        return SECURITY_ERROR_GUI_INIT_FAILED;
    }

    // 2. Create Menu Bar
    gui->menu_bar = create_menu_bar(gui->main_security_window);
    if (gui->menu_bar) {
        window_t* file_menu = add_menu(gui->menu_bar, "File");
        if (file_menu) {
            add_menu_item(file_menu, "Exit", on_menu_file_exit_click, NULL);
        }
        window_t* help_menu = add_menu(gui->menu_bar, "Help");
        if (help_menu) {
            add_menu_item(help_menu, "About", on_menu_help_about_click, NULL);
        }
    }

    // 3. Create Status Bar
    gui->status_bar = create_status_bar(gui->main_security_window, 20);
    if (gui->status_bar) {
        int panel_widths[] = {150, 200, -1}; // -1 for remaining width
        set_status_bar_panels(gui->status_bar, 3, panel_widths);
        set_status_bar_panel_text(gui->status_bar, 0, "Status: OK", 0xFF00FF00); // Green
        set_status_bar_panel_text(gui->status_bar, 1, "Events: 0", 0xFFFFFFFF); // White
        set_status_bar_panel_text(gui->status_bar, 2, "Version: 1.0", 0xFFFFFFFF);
    }

    // 4. Create Tab Control (assuming a tab_control_widget exists)
    gui->tab_control = create_panel_widget(gui->main_security_window, 0, 30, 780, 500); // Below menu bar
    if (!gui->tab_control) return SECURITY_ERROR_GUI_INIT_FAILED;
    set_window_background_color(gui->tab_control, 0xFFEEEEEE); // Light gray for tabs area

    // 5. Create Security Dashboard Tab
    gui->security_dashboard_tab = create_panel_widget(gui->tab_control, 10, 10, 760, 480);
    set_window_background_color(gui->security_dashboard_tab, 0xFFFFFFFF); // White
    // Add widgets to Dashboard tab
    gui->security_status_label = create_label_widget(gui->security_dashboard_tab, 10, 10, 300, 20, "System Status: Initializing...");
    set_label_text_color(gui->security_status_label, 0xFF0000FF); // Blue
    gui->total_events_label = create_label_widget(gui->security_dashboard_tab, 10, 40, 300, 20, "Total Events: 0");
    gui->event_log_list = create_list_widget(gui->security_dashboard_tab, 10, 70, 700, 300);
    set_on_item_select_event(gui->event_log_list, on_firewall_rule_list_select, NULL);
    // gui->event_log_scrollbar = create_scrollbar_widget(gui->security_dashboard_tab, 715, 70, 300, SCROLLBAR_VERTICAL);
    // set_on_scrollbar_change_event(gui->event_log_scrollbar, on_event_log_scroll);

    // 6. Create Firewall Tab
    gui->firewall_tab = create_panel_widget(gui->tab_control, 10, 10, 760, 480);
    set_window_background_color(gui->firewall_tab, 0xFFF0F0F0); // Lighter gray
    // Add widgets to Firewall tab
    gui->firewall_rule_type_label = create_label_widget(gui->firewall_tab, 10, 10, 100, 20, "Rule Type:");
    gui->firewall_rule_type_input = create_text_input_widget(gui->firewall_tab, 120, 10, 150, 25, "IP_BASED", 32);
    gui->firewall_rule_input = create_text_input_widget(gui->firewall_tab, 10, 40, 260, 25, "Enter Rule (e.g., 192.168.1.1)", 64);
    gui->firewall_rule_desc_input = create_text_input_widget(gui->firewall_tab, 10, 70, 260, 25, "Description", 128);
    gui->firewall_add_button = create_button_widget(gui->firewall_tab, 10, 100, 120, 30, "Add Rule", 0xFF00AA00); // Green
    set_button_callback(gui->firewall_add_button, on_firewall_add_button_click);
    gui->firewall_remove_button = create_button_widget(gui->firewall_tab, 150, 100, 120, 30, "Remove Rule", 0xFFAA0000); // Red
    set_button_callback(gui->firewall_remove_button, on_firewall_remove_button_click);
    gui->firewall_rules_list = create_list_widget(gui->firewall_tab, 10, 140, 700, 300);
    set_on_item_select_event(gui->firewall_rules_list, on_firewall_rule_list_select, NULL);
    // gui->firewall_rules_scrollbar = create_scrollbar_widget(gui->firewall_tab, 715, 140, 300, SCROLLBAR_VERTICAL);

    // 7. Create Quantum Security Tab
    gui->quantum_security_tab = create_panel_widget(gui->tab_control, 10, 10, 760, 480);
    set_window_background_color(gui->quantum_security_tab, 0xFFE0E0FF); // Light blue
    gui->quantum_status_label = create_label_widget(gui->quantum_security_tab, 10, 10, 400, 20, "Quantum Shield: Inactive");
    gui->quantum_shield_status_checkbox = create_checkbox_widget(gui->quantum_security_tab, 10, 40, "Enable Quantum Shield", false);
    set_on_checkbox_change_event(gui->quantum_shield_status_checkbox, on_quantum_shield_checkbox_change);
    gui->quantum_gen_keys_button = create_button_widget(gui->quantum_security_tab, 10, 70, 150, 30, "Generate Keys", 0xFF0077FF);
    set_button_callback(gui->quantum_gen_keys_button, on_quantum_gen_keys_button_click);
    gui->quantum_encrypt_test_button = create_button_widget(gui->quantum_security_tab, 170, 70, 150, 30, "Encrypt Test", 0xFF0077FF);
    set_button_callback(gui->quantum_encrypt_test_button, on_quantum_encrypt_test_button_click);
    gui->quantum_decrypt_test_button = create_button_widget(gui->quantum_security_tab, 330, 70, 150, 30, "Decrypt Test", 0xFF0077FF);
    set_button_callback(gui->quantum_decrypt_test_button, on_quantum_decrypt_test_button_click);

    // 8. Create Fairshare Warden Button (on Dashboard or a dedicated tab)
    window_t* fairshare_button = create_button_widget(gui->security_dashboard_tab, 500, 10, 200, 30, "Open Fairshare Manager", 0xFFFFAA00);
    set_button_callback(fairshare_button, on_fairshare_manager_button_click);
    gui->fairshare_warden_gui_window_ref = NULL; // Initially no Fairshare GUI window open

    // Set initial active tab
    // set_window_visible(gui->security_dashboard_tab, true);
    // set_window_visible(gui->firewall_tab, false);
    // set_window_visible(gui->quantum_security_tab, false);

    printf("Castle Security GUI initialized successfully.\n");
    return SECURITY_SUCCESS;
}

void shutdown_security_gui(castle_security_system_t* sys) {
    printf("Shutting down Castle Security GUI...\n");
    security_gui_context_t* gui = &sys->gui_context;

    if (gui->fairshare_warden_gui_window_ref) {
        destroy_window(gui->fairshare_warden_gui_window_ref);
        gui->fairshare_warden_gui_window_ref = NULL;
    }

    // Destroy main window, which should recursively destroy all children
    if (gui->main_security_window) {
        destroy_window(gui->main_security_window);
        gui->main_security_window = NULL;
    }

    // Reset all pointers
    memset(gui, 0, sizeof(security_gui_context_t));

    printf("Castle Security GUI shutdown complete.\n");
}

// --- GUI Event Callbacks Implementations ---

void on_security_event_received_gui_callback(event_stream_entry_t* event) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys || !sys->gui_context.event_log_list || !sys->gui_context.status_bar) {
        return; // GUI not initialized or widgets missing
    }

    char time_str[32];
    format_time(event->timestamp, time_str, sizeof(time_str));

    char log_entry[512];
    snprintf(log_entry, sizeof(log_entry), "[%s] %s: %s",
             time_str, security_event_type_to_str(event->event_type), event->details);

    list_widget_add_item(sys->gui_context.event_log_list, log_entry, NULL); // No specific data for now

    // Update status bar
    char status_text[64];
    snprintf(status_text, sizeof(status_text), "Events: %d", list_widget_get_item_count(sys->gui_context.event_log_list));
    set_status_bar_panel_text(sys->gui_context.status_bar, 1, status_text, 0xFFFFFFFF);

    // Update total events label
    char total_events_text[64];
    snprintf(total_events_text, sizeof(total_events_text), "Total Events: %d", list_widget_get_item_count(sys->gui_context.event_log_list));
    set_label_text(sys->gui_context.total_events_label, total_events_text);

    // Show alert dialog for critical events
    if (event->event_type == EVENT_SECURITY_BREACH || event->event_type == EVENT_INTRUSION_ATTEMPT ||
        event->event_type == EVENT_LATERAL_MOVEMENT_DETECTED || event->event_type == EVENT_RESOURCE_QUOTA_VIOLATION) { // NEW
        wchar_t title[] = L"Security Alert!";
        wchar_t wdetails[256];
        mbstowcs(wdetails, event->details, sizeof(wdetails));
        show_message_box(sys->gui_context.main_security_window, title, wdetails, 0); // Assuming 0 is MESSAGE_BOX_ERROR
    }
}

void on_firewall_add_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys || !sys->gui_context.firewall_rule_input || !sys->gui_context.firewall_rule_type_input || !sys->gui_context.firewall_rule_desc_input) return;

    char* rule_text = get_text_input_text(sys->gui_context.firewall_rule_input);
    char* type_text = get_text_input_text(sys->gui_context.firewall_rule_type_input);
    char* desc_text = get_text_input_text(sys->gui_context.firewall_rule_desc_input);

    // --- IMPROVEMENT: GUI Input Validation ---
    if (!validate_firewall_rule_input(rule_text, type_text)) {
        wchar_t title[] = L"Input Validation Error";
        wchar_t msg[] = L"Invalid rule format or type. Please check your input.";
        show_message_box(btn->parent, title, msg, 0); // Assuming 0 is MESSAGE_BOX_WARNING
        if (rule_text) kfree(rule_text);
        if (type_text) kfree(type_text);
        if (desc_text) kfree(desc_text);
        return;
    }

    if (rule_text && type_text && desc_text && strlen(rule_text) > 0) {
        security_rule_type_t rule_type = RULE_IP_BASED; // Default
        if (strcmp(type_text, "PORT_BASED") == 0) rule_type = RULE_PORT_BASED;
        else if (strcmp(type_text, "PROTOCOL_BASED") == 0) rule_type = RULE_PROTOCOL_BASED;
        else if (strcmp(type_text, "CONTENT_BASED") == 0) rule_type = RULE_CONTENT_BASED;
        else if (strcmp(type_text, "BEHAVIOR_BASED") == 0) rule_type = RULE_BEHAVIOR_BASED;
        else if (strcmp(type_text, "EBPF_FILTERED") == 0) rule_type = RULE_EBPF_FILTERED;
        else if (strcmp(type_text, "SIGNATURE_BASED") == 0) rule_type = RULE_SIGNATURE_BASED;
        else if (strcmp(type_text, "QUANTUM_ENFORCED") == 0) rule_type = RULE_QUANTUM_ENFORCED;
        // Add more type parsing as needed

        sys->modules.firewall_storage.add(rule_text, rule_type, desc_text);
        list_widget_add_item(sys->gui_context.firewall_rules_list, rule_text, NULL); // Add to GUI list
        set_text_input_text(sys->gui_context.firewall_rule_input, ""); // Clear input
        set_text_input_text(sys->gui_context.firewall_rule_desc_input, ""); // Clear input
    } else {
        wchar_t title[] = L"Input Error";
        wchar_t msg[] = L"Rule text cannot be empty!";
        show_message_box(btn->parent, title, msg, 0); // Assuming 0 is MESSAGE_BOX_WARNING
    }

    if (rule_text) kfree(rule_text);
    if (type_text) kfree(type_text);
    if (desc_text) kfree(desc_text);
}

void on_firewall_remove_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys || !sys->gui_context.firewall_rules_list) return;

    void* selected_item_data = list_widget_get_selected_item_data(sys->gui_context.firewall_rules_list);
    if (selected_item_data) {
        // In a real scenario, selected_item_data would contain the actual rule or its ID
        // For now, we'll just simulate removal and remove from GUI list
        char* rule_to_remove_text = list_widget_get_selected_item_text(sys->gui_context.firewall_rules_list);
        if (rule_to_remove_text) {
            sys->modules.firewall_storage.remove(rule_to_remove_text, RULE_IP_BASED); // Example removal
            list_widget_remove_selected_item(sys->gui_context.firewall_rules_list); // Remove from GUI list
            printf("Removed selected firewall rule from GUI list: %s.\n", rule_to_remove_text);
            kfree(rule_to_remove_text);
        }
    } else {
        wchar_t title[] = L"Selection Error";
        wchar_t msg[] = L"No rule selected to remove.";
        show_message_box(btn->parent, title, msg, 0);
    }
}

void on_firewall_rule_list_select(window_t* list_widget, void* item_data, void* user_data) {
    printf("Firewall Rule List: Item selected (data: %p)\n", item_data);
    // In a real app, you'd populate the input fields with the selected rule's details
}

void on_quantum_shield_checkbox_change(window_t* checkbox_win, bool new_state) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;

    atomic_store(&sys->modules.quantum_shield.active, new_state);
    if (new_state) {
        set_label_text(sys->gui_context.quantum_status_label, "Quantum Shield: Active");
        set_label_text_color(sys->gui_context.quantum_status_label, 0xFF00FF00); // Green
        printf("Quantum Shield Enabled.\n");
    } else {
        set_label_text(sys->gui_context.quantum_status_label, "Quantum Shield: Inactive");
        set_label_text_color(sys->gui_context.quantum_status_label, 0xFFFF0000); // Red
        printf("Quantum Shield Disabled.\n");
    }
}

void on_quantum_gen_keys_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;

    security_result_t res = sys->modules.quantum_shield.generate_keys(&sys->modules.quantum_shield.ctx);
    if (res == SECURITY_SUCCESS) {
        wchar_t title[] = L"Quantum Keys";
        wchar_t msg[] = L"Quantum keys generated successfully!";
        show_message_box(btn->parent, title, msg, 0);
    } else {
        wchar_t title[] = L"Quantum Keys Error";
        wchar_t msg[] = L"Failed to generate quantum keys.";
        show_message_box(btn->parent, title, msg, 0);
        sys->event_stream.publish(EVENT_QUANTUM_KEY_GEN_FAILED, "Quantum key generation failed.");
    }
}

void on_quantum_encrypt_test_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;

    uint8_t plaintext[] = "Test data for quantum encryption.";
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;

    security_result_t res = sys->modules.quantum_shield.encrypt_data(
        &sys->modules.quantum_shield.ctx, plaintext, sizeof(plaintext), &ciphertext, &ciphertext_len);

    if (res == SECURITY_SUCCESS && ciphertext) {
        wchar_t title[] = L"Quantum Encrypt";
        wchar_t msg[128];
        swprintf(msg, sizeof(msg) / sizeof(wchar_t), L"Encryption successful! Ciphertext length: %zu", ciphertext_len);
        show_message_box(btn->parent, title, msg, 0);
        free(ciphertext);
    } else {
        wchar_t title[] = L"Quantum Encrypt Error";
        wchar_t msg[] = L"Failed to encrypt data.";
        show_message_box(btn->parent, title, msg, 0);
        sys->event_stream.publish(EVENT_QUANTUM_ENCRYPT_FAILED, "Quantum encryption test failed.");
    }
}

void on_quantum_decrypt_test_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;

    // For a real test, you'd encrypt first, then decrypt the result.
    uint8_t example_ciphertext[] = "Encrypted example data.";
    uint8_t* decrypted_plaintext = NULL;
    size_t decrypted_len = 0;

    security_result_t res = sys->modules.quantum_shield.decrypt_data(
        &sys->modules.quantum_shield.ctx, example_ciphertext, sizeof(example_ciphertext), &decrypted_plaintext, &decrypted_len);

    if (res == SECURITY_SUCCESS && decrypted_plaintext) {
        wchar_t title[] = L"Quantum Decrypt";
        wchar_t msg[128];
        swprintf(msg, sizeof(msg) / sizeof(wchar_t), L"Decryption successful! Plaintext: %s", (char*)decrypted_plaintext);
        show_message_box(btn->parent, title, msg, 0);
        free(decrypted_plaintext);
    } else {
        wchar_t title[] = L"Quantum Decrypt Error";
        wchar_t msg[] = L"Failed to decrypt data.";
        show_message_box(btn->parent, title, msg, 0);
    }
}

void on_fairshare_manager_button_click(window_t* btn, const char* param) {
    castle_security_system_t* sys = get_security_system_instance();
    if (!sys) return;
    sys->open_fairshare_manager();
}

void on_menu_file_exit_click(window_t* btn, const char* param) {
    printf("Menu: File -> Exit clicked. Initiating system shutdown.\n");
    castle_security_system_t* sys = get_security_system_instance();
    sys->shutdown();
}

void on_menu_help_about_click(window_t* btn, const char* param) {
    printf("Menu: Help -> About clicked.\n");
    wchar_t title[] = L"About Castle Security";
    wchar_t msg[256];
    swprintf(msg, sizeof(msg) / sizeof(wchar_t), L"Castle Security System\nVersion %d.%d.%d\n\n" L"A robust security solution for your digital kingdom.\n" L"Developed by Royal Engineers.", CASTLE_SECURITY_VERSION_MAJOR, CASTLE_SECURITY_VERSION_MINOR, CASTLE_SECURITY_VERSION_PATCH);
    show_message_box(btn->parent, title, msg, 0); // Assuming 0 is MESSAGE_BOX_INFO
}

// --- Public API Functions ---

security_result_t init_security_system(void) {
    // This function simply calls the central system's initialize operation.
    // It acts as the main entry point for initializing the entire security system.
    castle_security_system_t* sys = get_security_system_instance();
    if (pthread_mutex_init(&sys->state.init_lock, NULL) != 0) {
        fprintf(stderr, "Error: Failed to initialize global init mutex.\n");
        return SECURITY_ERROR_GENERIC_FAILURE;
    }
    atomic_store(&sys->state.initialized, false); // Ensure it's false before init
    atomic_store(&sys->state.active_modules, 0);

    sys->initialize(); // Call the internal initialization routine
    if (atomic_load(&sys->state.initialized)) {
        return SECURITY_SUCCESS;
    } else {
        return SECURITY_ERROR_GENERIC_FAILURE; // Or a more specific error from init
    }
}

castle_security_system_t* get_security_system_instance(void) {
    // This implements a simple singleton pattern.
    // The instance is statically allocated and returned.
    // Initialization is handled by init_security_system.
    return g_security_system;
}

// --- Example Main Function (for testing, not part of the module itself) ---
/*
int main() {
    printf("Starting Castle Security System initialization...\n");
    security_result_t res = init_security_system();

    if (res == SECURITY_SUCCESS) {
        printf("Castle Security System initialized successfully.\n");

        castle_security_system_t* sys = get_security_system_instance();

        // Simulate some events
        sys->event_stream.publish(EVENT_FIREWALL_ALERT, "Suspicious connection attempt from 1.2.3.4");
        sys->event_stream.publish(EVENT_INTRUSION_ATTEMPT, "Failed login on admin account.");
        sys->event_stream.publish(EVENT_MALWARE_DETECTED, "Virus 'Evil.exe' detected in downloads.");
        sys->event_stream.publish(EVENT_SECURITY_BREACH, "Critical vulnerability exploited!");

        // Test some module operations via GUI callbacks
        // Simulate adding a firewall rule via GUI
        if (sys->gui_context.firewall_rule_input && sys->gui_context.firewall_rule_type_input && sys->gui_context.firewall_rule_desc_input) {
            set_text_input_text(sys->gui_context.firewall_rule_input, "10.0.0.1");
            set_text_input_text(sys->gui_context.firewall_rule_type_input, "IP_BASED");
            set_text_input_text(sys->gui_context.firewall_rule_desc_input, "Blocked internal test IP");
            on_firewall_add_button_click(sys->gui_context.firewall_add_button, NULL);

            set_text_input_text(sys->gui_context.firewall_rule_input, "8080");
            set_text_input_text(sys->gui_context.firewall_rule_type_input, "PORT_BASED");
            set_text_input_text(sys->gui_context.firewall_rule_desc_input, "Blocked high port");
            on_firewall_add_button_click(sys->gui_context.firewall_add_button, NULL);

            set_text_input_text(sys->gui_context.firewall_rule_input, "INVALID_IP"); // Test validation
            set_text_input_text(sys->gui_context.firewall_rule_type_input, "IP_BASED");
            set_text_input_text(sys->gui_context.firewall_rule_desc_input, "Invalid IP test");
            on_firewall_add_button_click(sys->gui_context.firewall_add_button, NULL);
        }

        // Simulate quantum shield activation
        if (sys->gui_context.quantum_shield_status_checkbox) {
            set_checkbox_checked(sys->gui_context.quantum_shield_status_checkbox, true);
            on_quantum_shield_checkbox_change(sys->gui_context.quantum_shield_status_checkbox, true);
        }
        if (sys->gui_context.quantum_gen_keys_button) {
            on_quantum_gen_keys_button_click(sys->gui_context.quantum_gen_keys_button, NULL);
        }
        if (sys->gui_context.quantum_encrypt_test_button) {
            on_quantum_encrypt_test_button_click(sys->gui_context.quantum_encrypt_test_button, NULL);
        }
        if (sys->gui_context.quantum_decrypt_test_button) {
            on_quantum_decrypt_test_button_click(sys->gui_context.quantum_decrypt_test_button, NULL);
        }

        // Simulate opening Fairshare Manager
        // Note: create_fairshare_warden_window is a dummy GUI function,
        // so this will only print messages unless a real GUI framework is linked.
        sys->open_fairshare_manager();
        sys->update_resource_displays();
        sys->close_fairshare_manager();


        // Simulate a kernel error
        sys->handle_kernel_error(101);

        // Simulate module load/unload
        dro_module_t test_module = {"TestModule", NULL};
        sys->load_module(&test_module);
        sys->unload_module(&test_module);

        // Simulate emergency lockdown (now advanced and non-blocking)
        sys->emergency_lockdown();

        // Demonstrate Patrol's new functions
        printf("\n--- Demonstrating Patrol's Training and Tuning ---\n");
        char sample_network_data[] = "Sample network flow data for training.";
        sys->modules.patrol.train_detection_model(sample_network_data, sizeof(sample_network_data));
        sys->modules.patrol.fine_tune_detection_parameters(75); // Set to a higher tuning level
        sys->modules.patrol.set_workload_level(3); // Set to high workload
        // Trigger detection via thread
        atomic_store(&sys->modules.patrol.trigger_detection, true);
        pthread_mutex_lock(&sys->modules.patrol.thread_lock);
        pthread_cond_signal(&sys->modules.patrol.thread_cond);
        pthread_mutex_unlock(&sys->modules.patrol.thread_lock);

        // Demonstrate IAM module
        printf("\n--- Demonstrating IAM Module ---\n");
        if (sys->modules.iam.authenticate_user("admin", "securepass")) {
            printf("IAM: Admin authenticated successfully.\n");
            sys->modules.iam.authorize_action("admin", "firewall_rules", "modify");
        } else {
            printf("IAM: Admin authentication failed.\n");
        }
        sys->modules.iam.authenticate_user("guest", "wrongpass");
        sys->modules.iam.authenticate_user("auditor", "auditpass");
        iam_user_account_t* admin_user = sys->modules.iam.get_user_by_uid(CASTLE_ADMIN_UID);
        if (admin_user) {
            printf("IAM: Retrieved admin user by UID: %s (Role: %s)\n", admin_user->username, admin_user->role);
        }
        sys->modules.iam.remove_user("guest");
        sys->modules.iam.add_user("new_user", "newpass", "user", 0);

        // Demonstrate Database module
        printf("\n--- Demonstrating Database Module ---\n");
        sys->modules.database.store_data("security_logs", "Log entry: Test data", strlen("Log entry: Test data"));
        sys->modules.database.execute_query("SELECT * FROM security_events WHERE type='intrusion'");

        // Demonstrate Fairshare Warden resource quotas
        printf("\n--- Demonstrating Fairshare Warden Resource Quotas ---\n");
        sys->modules.fairshare_warden.set_resource_quota("WebServers", 0.6, 1024 * 1024 * 256, 1024 * 1024 * 50);
        sys->modules.fairshare_warden.monitor_resource_usage();
        sys->modules.fairshare_warden.enforce_fairshare_rules();
        sys->modules.fairshare_warden.detect_violations(); // May trigger a violation event

        // Simulate some packet processing to test sk_buff lock
        printf("\n--- Simulating Firewall Packet Processing ---\n");
        void* dummy_sk_buff = (void*)0xDEADBEEF; // Represents a kernel sk_buff
        sys->modules.firewall.process_packet(dummy_sk_buff);


        printf("\nAllowing background threads to run for a few seconds...\n");
        sleep(10); // Give background threads time to run their periodic tasks

        printf("\nShutting down Castle Security System...\n");
        sys->shutdown();
    } else {
        fprintf(stderr, "Castle Security System initialization failed with error: %d\n", res);
    }

    return 0;
}
*/
