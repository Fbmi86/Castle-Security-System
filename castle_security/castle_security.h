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

#ifndef CASTLE_SECURITY_H
#define CASTLE_SECURITY_H

// --- Standard C Library Includes ---
#include <stdatomic.h> // For _Atomic and atomic_uint_fast32_t
#include <pthread.h>   // For pthread_mutex_t, pthread_rwlock_t, pthread_cond_t, pthread_t
#include <stdint.h>    // For uint8_t, uint32_t
#include <limits.h>    // For PATH_MAX
#include <assert.h>    // For static_assert
#include <time.h>      // For time_t
#include <stdbool.h>   // For bool
#include <stddef.h>    // For size_t
#include <wchar.h>     // For wchar_t (used by GUI dialogs)

// --- Project-Specific Header Includes ---
// Assuming these paths are correct relative to the project root
#include "../kernel/kernel.h"           // Assumed to include kernel_common_defs.h
#include "../kernel/kernel_common_defs.h" // Includes sdkk_error_t, uid_t, gid_t, pid_t, rect_t, color_t, spinlock_t, list_head
#include "../syscall/syscall.h"
#include "../debug/debug.h"
#include "../checksum/crc32.h"
#include "../signature/signature.h"
#include "../secureboot/secureboot.h"
#include "../security/sha256.h" // For SHA256_DIGEST_LENGTH
#include "../openssl/evp.h"
#include "../openssl/x509.h"
#include "../openssl/sha.h"
#include <oqs/oqs.h> // For OQS_KEM, OQS_SIG (liboqs) - Placeholder, actual linking needed
#include "../time/time.h"
#include "../sdk/doors_sdk.h"
#include "../scheduler/scheduler.h"
#include "../kernel/spinlock/spinlock.h"

// --- GUI Header Includes ---
// IMPORTANT: gui.h must be included first as it defines window_t, rect_t, color_t
#include "../gui/gui.h"
#include "../gui/widgets/text_input_widget.h"
#include "../gui/widgets/status_bar_widget.h"
#include "../gui/widgets/scrollbar_widget.h"
#include "../gui/widgets/panel_widget.h"
#include "../gui/widgets/menu_bar_widget.h"
#include "../gui/widgets/list_widget.h"
#include "../gui/widgets/gui_label_widget.h"
#include "../gui/widgets/checkbox_widget.h"
#include "../gui/widgets/button_widget.h"
#include "../gui/castle_gui.h"        // Main castle security GUI functions
#include "../gui/fairshare_warden_gui.h" // Fairshare Warden GUI functions
#include "../gui/gui_accessibility.h"
#include "../gui/gui_animation.h"
#include "../gui/gui_dialogs.h"
#include "../gui/gui_i18n.h"
#include "../gui/icons_gui.h"
#include "../gui/gui_input.h"

// --- Constants ---
#define CASTLE_SECURITY_VERSION_MAJOR 1
#define CASTLE_SECURITY_VERSION_MINOR 0
#define CASTLE_SECURITY_VERSION_PATCH 0
#define SECURITY_HASH_SIZE SHA256_DIGEST_LENGTH
#define SECURITY_MAX_RULE_LENGTH 128
#define SECURITY_DYNAMIC_GROWTH_FACTOR 2
#define MAX_SYSCALLS 256
#define POOL_BLOCK_SIZE 256
#define MAX_MODULES 32
#ifndef MAX_FAIRSHARE_GROUPS
#define MAX_FAIRSHARE_GROUPS 16 // Default definition for MAX_FAIRSHARE_GROUPS
#endif

// --- NEW FEATURE: Fixed UIDs for Important Users ---
#define CASTLE_ADMIN_UID 1000
#define CASTLE_AUDITOR_UID 1001
#define CASTLE_GUEST_UID 1002
#define CASTLE_SYSTEM_UID 0 // Root/System user

// --- Error Codes ---
typedef enum {
    SECURITY_SUCCESS = 0,
    SECURITY_ERROR_INVALID_ARGS,
    SECURITY_ERROR_OUT_OF_MEMORY,
    SECURITY_ERROR_MODULE_LOAD_FAILED,
    SECURITY_ERROR_CRYPTO_OPERATION,
    SECURITY_ERROR_QUANTUM_FAILURE,
    SECURITY_ERROR_NOT_INITIALIZED,
    SECURITY_ERROR_ALREADY_INITIALIZED,
    SECURITY_ERROR_MUTEX_LOCK_FAILED,
    SECURITY_ERROR_RWLOCK_FAILED,
    SECURITY_ERROR_NOT_FOUND,
    SECURITY_ERROR_GENERIC_FAILURE,
    SECURITY_ERROR_GUI_INIT_FAILED,
    SECURITY_ERROR_TPM_HSM_FAILURE,
    SECURITY_ERROR_MQTT_TLS_FAILURE,
    SECURITY_ERROR_DB_CONNECTION_FAILED,
    SECURITY_ERROR_USER_EXISTS, // NEW
    SECURITY_ERROR_USER_NOT_FOUND, // NEW
    SECURITY_ERROR_RESOURCE_LIMIT_EXCEEDED // NEW
} security_result_t;

// --- Security Event Types ---
typedef enum {
    EVENT_NONE = 0,
    EVENT_FIREWALL_ALERT,
    EVENT_INTRUSION_ATTEMPT,
    EVENT_MALWARE_DETECTED,
    EVENT_DATA_LEAK_PREVENTED,
    EVENT_SYSTEM_RESTORED,
    EVENT_SECURITY_BREACH,
    EVENT_POLICY_UPDATE,
    EVENT_MODULE_LOADED,
    EVENT_MODULE_UNLOADED,
    EVENT_RESOURCE_VIOLATION,
    EVENT_QUANTUM_KEY_GEN_FAILED,
    EVENT_QUANTUM_ENCRYPT_FAILED,
    EVENT_LATERAL_MOVEMENT_DETECTED,
    EVENT_VULNERABILITY_DETECTED,
    EVENT_PATCH_APPLIED,
    EVENT_SOAR_RESPONSE_INITIATED,
    EVENT_SECURE_MESSAGE_SENT,
    EVENT_DB_ACCESS_DENIED,
    EVENT_IAM_AUTH_FAILED,
    EVENT_RESOURCE_QUOTA_VIOLATION, // NEW
    EVENT_CRASH_RECOVERY_INITIATED, // NEW
    _EVENT_TYPE_COUNT
} security_event_type_t;

// --- Security Rule Types ---
typedef enum {
    RULE_IP_BASED = 0,
    RULE_PORT_BASED,
    RULE_PROTOCOL_BASED,
    RULE_CONTENT_BASED,
    RULE_BEHAVIOR_BASED,
    RULE_EBPF_FILTERED,
    RULE_SIGNATURE_BASED,
    RULE_QUANTUM_ENFORCED
} security_rule_type_t;

/**
 * @brief Represents a single entry in the security event stream.
 * @note Using fixed-length strings like `details[256]` can lead to truncation
 *       if the message is longer. For a production system, consider dynamic
 *       allocation (e.g., `char* details` and `strdup`) with proper memory
 *       management, or a more robust serialization format.
 */
typedef struct {
    security_event_type_t event_type; ///< Type of the event
    char details[256];                ///< Details of the event (fixed size, potential truncation)
    time_t timestamp;                 ///< Timestamp of the event
} event_stream_entry_t;

// --- Event Queue for Threading ---
typedef struct event_queue_node {
    event_stream_entry_t entry;
    struct event_queue_node* next;
} event_queue_node_t;

/**
 * @brief Central event streaming and processing system (Pub/Sub model).
 * @details Manages a historical log and a producer-consumer queue for real-time event processing.
 *          Includes a dedicated thread for processing events.
 */
typedef struct {
    event_stream_entry_t* entries; ///< List of entries (for historical log, not queue)
    size_t capacity;               ///< Total capacity of the historical log
    size_t count;                  ///< Current number of entries in the historical log
    pthread_mutex_t lock;          ///< Lock for concurrent access to 'entries' (historical log)

    // Threading for event processing (producer-consumer queue)
    event_queue_node_t* head;      ///< Head of the event queue
    event_queue_node_t* tail;      ///< Tail of the event queue
    pthread_mutex_t queue_lock;    ///< Lock for event queue operations
    pthread_cond_t queue_cond;     ///< Condition variable to signal new events
    pthread_t processing_thread;   ///< The dedicated event processing thread
    _Atomic bool processing_active; ///< Flag to control event processing thread lifecycle

    // Function pointers for pub/sub operations
    void (*subscribe)(security_event_type_t type, void (*callback)(event_stream_entry_t*));
    void (*publish)(security_event_type_t type, const char* message);
} event_stream_t;

/**
 * @brief Cleans up and frees resources associated with an event_stream_t.
 * @param stream Pointer to the event_stream_t structure.
 */
void event_stream_cleanup(event_stream_t* stream); // NEW

// --- Memory Pool ---
typedef struct {
    void* buffer;       ///< Contiguous memory buffer
    size_t block_size; ///< Size of each block
    size_t capacity;   ///< Total number of blocks
    size_t used;       ///< Number of used blocks
    pthread_mutex_t lock; ///< Lock for concurrent access
} memory_pool_t;

/**
 * @brief Context for Post-Quantum Cryptography (PQC) operations.
 * @details Encapsulates OQS library KEM and Signature objects, and key buffers.
 *          Uses a read-write lock for thread-safe key management.
 */
typedef struct {
    OQS_KEM* kem;           ///< Key Encapsulation Mechanism (e.g., Kyber)
    OQS_SIG* sig;           ///< Digital Signature (e.g., Dilithium)
    uint8_t* public_key;    ///< Public key buffer
    uint8_t* secret_key;    ///< Secret key buffer
    size_t public_key_len;  ///< Length of public key
    size_t secret_key_len;  ///< Length of secret key
    pthread_rwlock_t key_lock; ///< Read-write lock for key management
} quantum_context_t;

/**
 * @brief Quantum Shield Module for advanced quantum-resistant security.
 * @details Provides functions for quantum-safe key generation, encryption,
 *          decryption, signing, and signature verification. Includes
 *          quantum-based anomaly detection and cache protection mechanisms.
 *          Operates with a dedicated background thread for continuous monitoring.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t quantum_protection_cycles;
    quantum_context_t ctx;

    // Function pointers for quantum operations
    security_result_t (*initialize_quantum_defense)(quantum_context_t* qctx); // Changed to pointer
    security_result_t (*generate_keys)(quantum_context_t* qctx);             // Changed to pointer
    security_result_t (*encrypt_data)(quantum_context_t* qctx, const uint8_t* plaintext, size_t plaintext_len, uint8_t** ciphertext, size_t* ciphertext_len);
    security_result_t (*decrypt_data)(quantum_context_t* qctx, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t** plaintext, size_t* plaintext_len);
    security_result_t (*sign_data)(quantum_context_t* qctx, const uint8_t* data, size_t data_len, uint8_t** signature, size_t* sig_len);
    security_result_t (*verify_signature)(quantum_context_t* qctx, const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len);

    // Quantum-based detection and cache protection
    security_result_t (*detect_quantum_anomalies)(void); ///< Detects subtle quantum-level anomalies
    security_result_t (*protect_cache)(void* cache_address, size_t cache_size); ///< Applies quantum-resistant cache protection

    // Threading for continuous quantum monitoring/protection
    pthread_t quantum_thread;
    _Atomic bool thread_running;
    pthread_mutex_t thread_lock; // For signaling thread
    pthread_cond_t thread_cond;  // For signaling thread
    _Atomic bool trigger_anomaly_detection; // Flag to trigger detection from main thread
    _Atomic bool trigger_cache_protection;  // Flag to trigger cache protection from main thread
} quantum_shield_t;

/**
 * @brief Represents a generic security entry (e.g., a firewall rule, a hash).
 * @note `description` is a fixed-length string, consider dynamic allocation for flexibility.
 */
typedef struct {
    char hash[SECURITY_HASH_SIZE];
    time_t timestamp;
    uint32_t flags; // Can store rule type
    char description[SECURITY_MAX_RULE_LENGTH];
} security_entry_t;

/**
 * @brief A generic list for security entries (e.g., blacklist, whitelist).
 * @details Uses dynamic array for storage and a mutex for thread-safe access.
 *          `atomic_count` provides lock-free reads of the current count.
 */
typedef struct {
    security_entry_t* entries;
    size_t capacity;
    size_t count;
    atomic_size_t atomic_count; // For atomic read of count
    pthread_mutex_t lock;
} security_list_t;

/**
 * @brief Cleans up and frees resources associated with a security_list_t.
 * @param list Pointer to the security_list_t structure.
 */
void security_list_cleanup(security_list_t* list); // NEW

// --- Security Modules (struct definitions as before) ---

/**
 * @brief Messenger module for secure and reliable communication.
 * @details Supports secure messaging protocols like MQTT with TLS.
 *          Includes conceptual support for inter-node synchronization.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t message_count;
    void (*send_alert)(security_event_type_t event, const char* message); // Changed to pointer
    void (*notify)(const char* subsystem, const char* message);           // Changed to pointer
    void (*broadcast)(security_event_type_t event);                      // Changed to pointer
    // New: Secure messaging with MQTT/TLS
    bool (*connect_mqtt_tls)(const char* broker_addr, int port, const char* cert_path); ///< Connects to MQTT broker with TLS
    void (*send_secure_message)(const char* topic, const char* message); ///< Sends message over secure channel
    _Atomic bool neighbor_sync_enabled; // NEW: For crash resistance config
    void (*sync_with_neighbors)(void); // NEW: Conceptual neighbor sync
} messenger_t;

/**
 * @brief Internal Monitor module for self-integrity and module health.
 * @details Continuously monitors the integrity and health of internal security modules.
 *          Operates with a dedicated background thread.
 */
typedef struct {
    _Atomic bool active;
    void (*health_check)(void);
    void (*integrity_verification)(void);
    void (*dependency_check)(void);
    // Internal module protection
    void (*self_integrity_check)(void);   ///< Verifies the integrity of the monitor itself
    void (*module_tamper_detection)(void); ///< Detects tampering with other security modules

    // Threading for continuous monitoring
    pthread_t monitor_thread;
    _Atomic bool thread_running;
    pthread_mutex_t thread_lock;
    pthread_cond_t thread_cond;
    _Atomic bool trigger_integrity_check; // Flag to trigger check from main thread
} internal_monitor_t;

/**
 * @brief Recovery module for system rollback, snapshots, and vulnerability management.
 * @details Provides capabilities for system restoration, configuration versioning,
 *          and proactive vulnerability patching. Includes periodic backup functionality.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t recovery_count;
    void (*module_recovery)(void);
    void (*system_rollback)(void);
    void (*state_restoration)(void);
    // New: Snapshot and versioning
    void (*create_snapshot)(const char* config_name);   ///< Creates a configuration snapshot
    void (*restore_from_snapshot)(const char* config_name); ///< Restores system from a snapshot
    // New: Vulnerability management and patching
    void (*manage_vulnerabilities)(void); ///< Scans for and manages system vulnerabilities
    void (*apply_patches)(void);         ///< Applies necessary security patches

    // NEW: For crash resistance config
    pthread_t backup_thread;
    _Atomic bool backup_thread_running;
    pthread_mutex_t backup_thread_lock;
    pthread_cond_t backup_thread_cond;
    time_t last_backup_time;
    uint32_t backup_interval_seconds; // Configurable interval
} recovery_t;

/**
 * @brief System Protector module for malware scanning and threat analysis.
 * @details Operates with a dedicated background thread for continuous scanning.
 */
typedef struct {
    _Atomic bool active;
    void (*scan)(void);
    void (*quarantine)(void);
    void (*analysis)(void);

    // Threading for background scans/analysis
    pthread_t protector_thread;
    _Atomic bool thread_running;
    pthread_mutex_t thread_lock;
    pthread_cond_t thread_cond;
    _Atomic bool trigger_scan; // Flag to trigger scan from main thread
} system_protector_t;

/**
 * @brief Firewall Storage module for managing firewall rules.
 * @details Stores and manages blacklist, whitelist, and suspicious lists.
 *          In a real system, this would use optimized data structures like hash tables
 *          or balanced trees for scalability. Uses read-write locks for concurrent access.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t rule_count;
    pthread_rwlock_t list_lock; ///< Read-write lock for rule lists
    security_list_t blacklist;
    security_list_t whitelist;
    security_list_t suspicious_list;
    void (*add)(const char* rule, security_rule_type_t type, const char* description); // Changed to pointer
    void (*remove)(const char* rule, security_rule_type_t type);                     // Changed to pointer
    void (*update)(const char* rule, security_rule_type_t type, const char* new_description); // Changed to pointer
    bool (*check)(security_list_t* list, const char* rule, security_rule_type_t type); // Changed to pointer, removed redundant first arg
} firewall_storage_t;

/**
 * @brief Inspection Unit module for deep packet inspection and policy enforcement.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t inspected_requests;
    void (*rule_analysis)(void);
    void (*security_enforcement)(void);
    void (*policy_optimization)(void);
    void (*reporting)(void);
} inspection_unit_t;

/**
 * @brief Kernel Bridge module for secure communication with the kernel.
 * @details Uses secure IPC mechanisms and validates messages.
 */
typedef struct {
    _Atomic bool active;
    pthread_mutex_t sync_lock;
    void (*sync)(void);
    void (*alert)(const char* message); // Changed to pointer
    void (*command_handler)(void);
    // New: Secure IPC and message validation
    void (*secure_ipc_send)(const void* data, size_t size); ///< Sends data securely to kernel
    bool (*validate_ipc_message)(const void* message, size_t size); ///< Validates incoming kernel messages
} kernel_bridge_t;

/**
 * @brief Sandbox module for secure execution environments.
 * @details Provides isolation policies including UID/GID, chroot, and syscall filtering.
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t sandbox_count;
    pthread_rwlock_t policy_lock; ///< Read-write lock for sandbox policies
    struct {
        uid_t isolated_uid;
        gid_t isolated_gid;
        char chroot_path[PATH_MAX];
        char allowed_syscalls[MAX_SYSCALLS][32]; // Array of syscall names
        size_t allowed_syscalls_count;
    } isolation_policy;
    void (*create)(const char* name, const char* base_dir); // Changed to pointer
    void (*destroy)(const char* name);                     // Changed to pointer
    bool (*execute_in_sandbox)(const char* sandbox_name, const char* command); // Changed to pointer
    void (*update_policy)(const char* sandbox_name);       // Changed to pointer
    void (*monitor_activity)(const char* sandbox_name);    // Changed to pointer
} sandbox_t;

/**
 * @brief Castle Journal module for logging, analysis, and SIEM integration.
 * @details Provides advanced log compression and integration with SIEM systems.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t log_entries;
    pthread_mutex_t log_lock; ///< Mutex for log access
    void (*record)(security_event_type_t event, const char* details); // Changed to pointer
    void (*retrieve)(time_t from, time_t to);
    void (*analyze)(void);
    // New: SIEM integration and advanced log compression
    void (*integrate_siem)(const char* siem_endpoint); ///< Integrates with external SIEM system
    void (*compress_logs)(void);                       ///< Applies advanced compression to log data
} castle_journal_t;

/**
 * @brief Firewall module for packet filtering.
 * @details Utilizes epoll for efficient I/O and a mutex for `sk_buff` access.
 */
typedef struct {
    _Atomic bool enabled;
    security_list_t rules;
    int epoll_fd;
    struct epoll_event* events; // Changed to pointer
    pthread_mutex_t sk_buff_lock; ///< Mutex to protect sk_buff access during packet processing
    void (*process_packet)(void* pkt); // Changed to pointer
} firewall_t;

/**
 * @brief Castle Wall module for access monitoring and intrusion prevention.
 * @details Uses read-write locks for access logs/data.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t unauthorized_attempts;
    pthread_rwlock_t access_lock; ///< Read-write lock for access logs/data
    void (*access_monitor)(void);
    void (*intrusion_prevention)(void);
    void (*threat_assessment)(void);
} castle_wall_t;

/**
 * @brief Watch Tower module for threat detection and anomaly detection.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t scan_frequency;
    void (*threat_detection)(void);
    void (*alert_handling)(security_event_type_t event);
    void (*anomaly_detection)(void);
} watch_tower_t;

/**
 * @brief Patrol module for data scanning and lateral movement detection.
 * @details Employs deep learning algorithms for increased detection accuracy.
 *          Equipped with dynamic workload adjustment.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t monitored_packets;
    void (*data_scan)(void);
    void (*suspicious_activity_handler)(void);
    void (*log_activity)(security_event_type_t event);
    // Lateral Movement Detection with Deep Learning
    void (*detect_lateral_movement)(void); ///< Detects lateral movement using deep learning algorithms
    void (*respond_lateral_movement)(void); ///< Initiates automated response to lateral movement
    // For training and tuning Lateral Movement Detection
    atomic_uint_fast32_t training_data_processed; ///< Amount of real data processed for training
    int tuning_level; ///< Level of fine-tuning applied (e.g., 0-100)
    void (*train_detection_model)(const void* real_data, size_t data_size); ///< Trains the detection model
    void (*fine_tune_detection_parameters)(int level); ///< Fine-tunes model parameters

    // NEW: Dynamic Workload Adjustment
    _Atomic int workload_level; // 0: idle, 1: low, 2: medium, 3: high (e.g., scan frequency/depth)
    void (*set_workload_level)(int level); // Function to set workload level

    // Threading for continuous lateral movement detection
    pthread_t patrol_thread;
    _Atomic bool thread_running;
    pthread_mutex_t thread_lock;
    pthread_cond_t thread_cond;
    _Atomic bool trigger_detection; // Flag to trigger detection from main thread
} patrol_t;

/**
 * @brief Guardian module for data encryption and access control.
 * @details Supports TPM and HSM for secure key management.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t protected_files;
    void (*encrypt_data)(void* data, size_t size); // Changed to pointer
    void (*decrypt_data)(void* data, size_t size); // Changed to pointer
    void (*access_control)(void);
    // New: TPM and HSM support for key management
    bool (*load_key_from_tpm)(uint8_t* key_buffer, size_t buffer_size); ///< Loads key securely from TPM
    bool (*generate_key_in_hsm)(uint32_t key_id); ///< Generates key securely within HSM
} guardian_t;

/**
 * @brief Security Unit module for attack mitigation and incident response.
 * @details Implements Security Orchestration, Automation, and Response (SOAR) capabilities.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t incidents_resolved;
    void (*attack_mitigation)(void);
    void (*resource_protection)(void);
    void (*emergency_response)(void);
    // New: SOAR (Security Orchestration, Automation, and Response)
    void (*automate_response)(security_event_type_t event); ///< Automates response actions based on event type
    void (*orchestrate_incident_response)(void); ///< Orchestrates complex incident response workflows
} security_unit_t;

/**
 * @brief Witch module for network device management and policy enforcement.
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t managed_devices;
    pthread_mutex_t network_lock;
    void (*device_registration)(void);
    void (*traffic_monitoring)(void);
    void (*policy_enforcement)(void);
} witch_t;

/**
 * @brief Arcane Scan module for advanced authentication methods.
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t verification_attempts;
    bool (*verify_with_token)(void);
    bool (*biometric_authentication)(void);
    bool (*location_based_verification)(void);
} arcane_scan_t;

/**
 * @brief Cipher Sentinel module for secure key generation and real-time cipher monitoring.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t encrypted_keys;
    void (*secure_key_generation)(void);
    void (*real_time_cipher_monitoring)(void);
    void (*decryption_protection)(void);
} cipher_sentinel_t;

/**
 * @brief Signature Verification module for cryptographic signature validation.
 * @details Supports new and emerging cryptographic standards.
 */
typedef struct {
    _Atomic bool initialized;
    // New: Support for new cryptographic standards (e.g., Post-Quantum Cryptography)
    bool (*verify_post_quantum_signature)(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t sig_len); ///< Verifies signatures using post-quantum algorithms
} signature_verification_t;

/**
 * @brief Shadow Gatekeeper module for secure execution of untrusted code.
 * @details Provides full sandboxing for WebAssembly (WASM) modules.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t monitored_packets;
    pthread_mutex_t gatekeeper_lock; ///< Mutex for gatekeeper operations
    _Atomic bool wasm_enabled; ///< Flag to indicate if WASM sandboxing is active
    void* wasm_module_handle; ///< Handle to the loaded WASM module runtime (conceptual)
    void (*load_wasm_filter)(const char* wasm_bytecode); ///< Loads a WASM bytecode filter
    void (*unload_wasm_filter)(void); ///< Unloads the WASM filter
    void (*process_with_wasm)(void* data, size_t size); ///< Processes data through the WASM filter in a sandbox
} shadow_gatekeeper_t;

/**
 * @brief Secure Boot module for verifying the integrity of the boot chain.
 */
typedef struct {
    _Atomic bool verified;
    atomic_uint_fast32_t boot_attempts;
    pthread_mutex_t verification_lock;
    struct {
        uint8_t hardware_hash[SHA256_DIGEST_LENGTH];
        uint8_t firmware_hash[SHA256_DIGEST_LENGTH];
        uint8_t kernel_hash[SHA256_DIGEST_LENGTH];
    } known_good_hashes;
    bool (*verify_hardware)(void);
    bool (*verify_firmware)(void);
    bool (*verify_kernel)(void);
    bool (*verify_boot_chain)(void);
    void (*recovery_boot)(void);
} secure_boot_t;

/**
 * @brief Phantom Hand module for hardware offloading and dynamic optimization.
 * @details Develops dynamic scheduling capabilities and optimizes energy consumption.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t offloaded_tasks;
    void (*configure_fpga)(void);
    void (*program_asic)(void);
    void (*offload_processing)(void* data, size_t size); // Changed to pointer
    // New: Dynamic scheduling and energy optimization
    void (*dynamic_schedule_tasks)(void); ///< Dynamically schedules tasks for optimal performance
    void (*optimize_power_consumption)(void); ///< Optimizes hardware power consumption
} phantom_hand_t;

/**
 * @brief Wisdom Flow module for applying backports and managing compatibility.
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t backported_features;
    void (*apply_backport)(const char* feature); // Changed to pointer
    void (*verify_compatibility)(void);
    void (*rollback_changes)(void);
} wisdom_flow_t;

/**
 * @brief Grumpy Frame module for hardware-level sandboxing.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t isolated_processes;
    void (*create_hardware_sandbox)(void);
    void (*isolate_process)(pid_t pid);
    void (*monitor_sandbox)(void);
} grumpy_frame_t;

/**
 * @brief Fast Barrier module for high-performance packet processing.
 * @details Utilizes XDP (eXpress Data Path) for optimized packet processing.
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t processed_packets;
    void (*load_ebpf_program)(const char* program); // Changed to pointer
    void (*configure_xdp_filter)(void); ///< Configures XDP filter for high-speed packet processing
    void (*optimize_packet_processing)(void); ///< Optimizes packet processing using XDP/eBPF
} fast_barrier_t;

/**
 * @brief Lazy Zoom module for intelligent load distribution and self-tuning.
 * @details Implements smart load balancing algorithms and self-adjustment mechanisms.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t balanced_connections;
    void (*distribute_traffic)(void);
    void (*add_server_node)(const char* node_address);    // Changed to pointer
    void (*remove_server_node)(const char* node_address); // Changed to pointer
    // New: Intelligent load distribution and self-tuning
    void (*apply_load_balancing)(void); ///< Applies intelligent load balancing algorithms
    void (*self_tune_system)(void);     ///< Self-tunes system parameters for optimal performance
} lazy_zoom_t;

/**
 * @brief Granite module for secure enclaves (SGX, SEV).
 */
typedef struct {
    _Atomic bool enabled;
    atomic_uint_fast32_t secured_enclaves;
    void (*initialize_sgx)(void);
    void (*setup_sev)(void);
    void (*create_secure_enclave)(void* data, size_t size); // Changed to pointer
} granite_t;

/**
 * @brief Spectre and Timing Attack Defense Module.
 * @details Implements mitigations and detection for speculative execution and timing side-channel attacks.
 *          Operates with a dedicated background thread.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t mitigated_attacks_count;
    pthread_mutex_t defense_lock; ///< Mutex for defense operations
    void (*enable_mitigations)(void); ///< Enables CPU-level mitigations
    void (*disable_mitigations)(void); ///< Disables CPU-level mitigations
    void (*detect_spectre_attack)(void); ///< Detects patterns indicative of Spectre attacks
    void (*detect_timing_attack)(void); ///< Detects timing side-channel attacks
    void (*apply_speculative_execution_hardening)(void); ///< Applies hardening techniques for speculative execution
    void (*apply_timing_noise)(void); ///< Introduces noise to timing measurements to thwart attacks

    // Threading for continuous detection
    pthread_t defense_thread;
    _Atomic bool thread_running;
    pthread_mutex_t thread_lock; // For signaling thread
    pthread_cond_t thread_cond;  // For signaling thread
    _Atomic bool trigger_detection; // Flag to trigger detection from main thread
} spectre_timing_defense_t;

/**
 * @brief Represents a resource quota policy for a group.
 * @details Defines limits for CPU, memory, and I/O bandwidth.
 */
typedef struct {
    char group_id[32];
    int priority;
    double cpu_share;      // Percentage (0.0 - 1.0)
    size_t memory_limit;   // Bytes
    size_t io_bandwidth;   // Bytes/second
    // Conceptual resource meters (actual implementation would be complex and OS-specific)
    void* cpu_meter;    // Placeholder for a resource meter object
    void* memory_meter; // Placeholder for a resource meter object
    void* io_meter;     // Placeholder for a resource meter object
} fairshare_group_policy_t; // NEW: Renamed for clarity

/**
 * @brief Fairshare Warden: Resource management and enforcement.
 * @details Adds advanced QoS policies and real-time monitoring.
 *          Manages resource quotas for different user groups or processes.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t managed_groups;
    pthread_rwlock_t policy_lock; ///< Read-write lock for fairshare policies
    void (*monitor_resource_usage)(void);
    void (*enforce_fairshare_rules)(void);
    void (*adjust_resource_allocation)(const char* group_id, int priority); // Changed to pointer
    void (*detect_violations)(void);
    void (*report_usage_statistics)(void);
    void (*update_gui_display)(void);
    // New: Advanced QoS and real-time monitoring
    void (*enforce_qos)(void);         ///< Enforces Quality of Service policies
    void (*get_realtime_metrics)(void); ///< Retrieves real-time resource usage metrics

    fairshare_group_policy_t group_policies[MAX_FAIRSHARE_GROUPS]; // Use the new struct
    size_t policy_count;
    window_t management_window; // Main Fairshare Warden GUI window

    // NEW: Function to set a resource quota for a group
    security_result_t (*set_resource_quota)(const char* group_id, double cpu_share, size_t memory_limit, size_t io_bandwidth);
} fairshare_warden_t;

/**
 * @brief Represents a user account in the IAM module.
 * @details Includes a fixed UID for important users.
 */
typedef struct {
    uid_t uid;
    char username[64];
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1]; // Hex string of SHA256
    char role[32];
    bool is_important_user; // NEW: Flag for fixed UID users
} iam_user_account_t; // NEW

/**
 * @brief Identity and Access Management (IAM) module.
 * @details Manages user identities, roles, authentication, and authorization.
 *          Supports fixed UIDs for important users.
 */
typedef struct {
    _Atomic bool active;
    atomic_uint_fast32_t authenticated_users;
    // Conceptual internal user/role database
    iam_user_account_t users[64]; // Simple array for demonstration
    size_t user_count;
    pthread_mutex_t user_db_lock; // NEW: Lock for user database access

    bool (*authenticate_user)(const char* username, const char* password); ///< Authenticates a user
    bool (*authorize_action)(const char* username, const char* resource, const char* action); ///< Authorizes a user action
    security_result_t (*add_user)(const char* username, const char* password, const char* role, uid_t fixed_uid); ///< Adds a new user, allows fixed UID
    security_result_t (*remove_user)(const char* username); ///< Removes a user
    iam_user_account_t* (*get_user_by_uid)(uid_t uid); // NEW: Get user by fixed UID
    iam_user_account_t* (*get_user_by_username)(const char* username); // NEW: Get user by username
} iam_module_t;

/**
 * @brief Independent Database Module.
 * @details Provides a secure and scalable independent database for security data.
 */
typedef struct {
    _Atomic bool active;
    char connection_string[256];
    void* db_handle; // Conceptual database connection handle
    bool (*connect_db)(const char* conn_str); ///< Establishes database connection
    void (*disconnect_db)(void); ///< Closes database connection
    security_result_t (*execute_query)(const char* query); ///< Executes a database query
    security_result_t (*store_data)(const char* table, const void* data, size_t data_size); ///< Stores data in the database
    void* (*retrieve_data)(const char* table, const char* criteria, size_t* data_size); ///< Retrieves data from the database
} database_module_t;

// --- NEW FEATURE: Crash Resistance Configuration ---
/**
 * @brief Configuration for system crash resistance and recovery.
 */
typedef struct {
    _Atomic bool auto_reboot;       ///< Automatically reboot on critical crash
    uint32_t backup_interval_s;     ///< Interval for system backups in seconds
    _Atomic bool quantum_backup_enabled; ///< Enable backup of quantum keys/state
    _Atomic bool neighbor_sync_enabled;  ///< Enable synchronization with neighbor nodes
} crash_recovery_config_t;

// --- GUI Context for Central Security System ---
typedef struct {
    window_t* main_security_window;
    window_t* menu_bar;
    window_t* status_bar;
    window_t* tab_control; // Assuming a tab control widget exists

    // Pointers to the main tab panels
    window_t* security_dashboard_tab;
    window_t* firewall_tab;
    window_t* intrusion_detection_tab;
    window_t* quantum_security_tab;
    window_t* system_monitor_tab;
    window_t* settings_tab;

    // Widgets within the Firewall tab
    window_t* firewall_rule_input; // text_input_widget
    window_t* firewall_add_button; // button_widget
    window_t* firewall_remove_button; // button_widget
    window_t* firewall_rules_list; // list_widget
    window_t* firewall_rules_scrollbar; // scrollbar_widget
    window_t* firewall_rule_type_label; // label_widget
    window_t* firewall_rule_type_input; // text_input_widget (for rule type)
    window_t* firewall_rule_desc_input; // text_input_widget (for description)

    // Widgets within the Security Dashboard tab
    window_t* event_log_list; // list_widget
    window_t* event_log_scrollbar; // scrollbar_widget
    window_t* security_status_label; // label_widget (e.g., "System Status: OK")
    window_t* quantum_shield_status_checkbox; // checkbox_widget
    window_t* total_events_label; // label_widget

    // Widgets within Quantum Security tab
    window_t* quantum_status_label; // label_widget
    window_t* quantum_gen_keys_button; // button_widget
    window_t* quantum_encrypt_test_button; // button_widget
    window_t* quantum_decrypt_test_button; // button_widget

    // Fairshare Warden GUI (managed by its own create function, but referenced here)
    // The fairshare_warden_t struct already holds its main window pointer.
    // This field here is for convenience if the main security system needs to open/close it.
    window_t* fairshare_warden_gui_window_ref;

    // Other common GUI elements
    window_t* alert_dialog_parent; // A window to parent alert dialogs
} security_gui_context_t;

/**
 * @brief The main structure representing the entire Castle Security System.
 * @details Contains the state, all security modules, and core system operations.
 *          Designed as a singleton.
 */
typedef struct {
    struct {
        _Atomic bool initialized;
        atomic_uint_fast32_t active_modules;
        pthread_mutex_t init_lock; ///< Mutex for system initialization
    } state;
    struct {
        firewall_t firewall;
        castle_wall_t castle_wall;
        watch_tower_t watch_tower;
        patrol_t patrol;
        guardian_t guardian;
        security_unit_t security_unit;
        messenger_t messenger;
        internal_monitor_t internal_monitor;
        recovery_t recovery;
        system_protector_t system_protector;
        firewall_storage_t firewall_storage;
        inspection_unit_t inspection_unit;
        kernel_bridge_t kernel_bridge;
        castle_journal_t castle_journal;
        signature_verification_t signature_verification;
        sandbox_t sandbox;
        secure_boot_t secure_boot;
        witch_t witch;
        arcane_scan_t arcane_scan;
        quantum_shield_t quantum_shield;
        cipher_sentinel_t cipher_sentinel;
        shadow_gatekeeper_t shadow_gatekeeper;
        phantom_hand_t phantom_hand;
        wisdom_flow_t wisdom_flow;
        grumpy_frame_t grumpy_frame;
        fast_barrier_t fast_barrier;
        lazy_zoom_t lazy_zoom;
        granite_t granite;
        fairshare_warden_t fairshare_warden;
        spectre_timing_defense_t spectre_timing_defense; // Spectre and Timing Attack Defense
        iam_module_t iam;       // Identity and Access Management module
        database_module_t database; // Independent Database module
    } modules;
    // Core operations of the central system
    void (*initialize)(void); ///< Initializes the entire security system
    void (*shutdown)(void); ///< Shuts down and cleans up the entire security system
    void (*emergency_lockdown)(void); ///< Initiates an advanced emergency lockdown
    void (*update_security_policy)(void); ///< Updates global security policies
    void (*open_fairshare_manager)(void); ///< Opens the Fairshare Warden GUI manager
    void (*close_fairshare_manager)(void); ///< Closes the Fairshare Warden GUI manager
    void (*update_resource_displays)(void); ///< Updates resource usage displays in GUI
    sdkk_error_t (*handle_kernel_error)(sdkk_error_t error); ///< Handles kernel-level errors
    sdkk_error_t (*load_module)(const dro_module_t* module); ///< Dynamically loads a security module
    sdkk_error_t (*unload_module)(const dro_module_t* module); ///< Dynamically unloads a security module
    // Added features
    event_stream_t event_stream; ///< Central event streaming and processing system
    memory_pool_t mem_pool; ///< Global memory pool for efficient allocations
    security_gui_context_t gui_context; ///< GUI-related elements and state
    crash_recovery_config_t crash_config; // NEW: Crash resistance configuration
} castle_security_system_t;

// --- Function Declarations ---

/**
 * @brief Initializes the security system.
 * @return SECURITY_SUCCESS on success, error code otherwise.
 */
security_result_t init_security_system(void);
/**
 * @brief Creates a memory pool.
 * @param pool Pointer to the memory pool structure.
 * @param block_size Size of each block in bytes.
 * @param capacity Total number of blocks.
 * @return SECURITY_SUCCESS on success, error code otherwise.
 */
security_result_t memory_pool_init(memory_pool_t* pool, size_t block_size, size_t capacity); // Changed to pointer
/**
 * @brief Destroys a memory pool, freeing its allocated buffer.
 * @param pool Pointer to the memory pool structure.
 */
void memory_pool_destroy(memory_pool_t* pool); // Changed to pointer
/**
 * @brief Retrieves the singleton instance of the castle security system.
 * @return Pointer to the castle_security_system_t instance.
 */
castle_security_system_t* get_security_system_instance(void);
/**
 * @brief Initializes the GUI components of the security system.
 * @param sys Pointer to the castle_security_system_t instance.
 * @return SECURITY_SUCCESS on success, error code otherwise.
 */
security_result_t init_security_gui(castle_security_system_t* sys); // Changed to pointer
/**
 * @brief Shuts down and cleans up GUI components.
 * @param sys Pointer to the castle_security_system_t instance.
 */
void shutdown_security_gui(castle_security_system_t* sys); // Changed to pointer
/**
 * @brief Callback for security events to update the GUI.
 * @param event Pointer to the security event entry.
 */
void on_security_event_received_gui_callback(event_stream_entry_t* event); // Changed to pointer
/**
 * @brief Converts a security event type enum to a human-readable string.
 * @param event_type The event type.
 * @return A string representation of the event type.
 */
const char* security_event_type_to_str(security_event_type_t event_type); // Changed to pointer
/**
 * @brief Formats a time_t timestamp into a human-readable string.
 * @param timestamp The time_t value.
 * @param buffer The buffer to write the formatted string into.
 * @param buffer_size The size of the buffer.
 */
void format_time(time_t timestamp, char* buffer, size_t buffer_size); // Changed to pointer

// --- NEW FEATURE: GUI Input Validation Helper ---
/**
 * @brief Validates a firewall rule input string based on its type.
 * @param rule_text The rule string (e.g., IP address, port number).
 * @param type_text The string representation of the rule type (e.g., "IP_BASED").
 * @return true if the input is valid, false otherwise.
 */
bool validate_firewall_rule_input(const char* rule_text, const char* type_text);

// --- GUI Widget Callbacks (Examples) ---
void on_firewall_add_button_click(window_t* btn, const char* param);
void on_firewall_remove_button_click(window_t* btn, const char* param);
void on_firewall_rule_list_select(window_t* list_widget, void* item_data, void* user_data);
void on_quantum_shield_checkbox_change(window_t* checkbox_win, bool new_state);
void on_quantum_gen_keys_button_click(window_t* btn, const char* param);
void on_quantum_encrypt_test_button_click(window_t* btn, const char* param);
void on_quantum_decrypt_test_button_click(window_t* btn, const char* param);
void on_fairshare_manager_button_click(window_t* btn, const char* param);
void on_menu_file_exit_click(window_t* btn, const char* param);
void on_menu_help_about_click(window_t* btn, const char* param);

// --- Internal/Static Function Declarations (for central system operations) ---
// These are declared static in the .c file, but listed here for clarity of system operations
static void central_system_initialize(void);
static void central_system_shutdown(void);
static void central_system_emergency_lockdown(void);
static void central_system_update_security_policy(void);
static void central_system_open_fairshare_manager(void);
static void central_system_close_fairshare_manager(void);
static void central_system_update_resource_displays(void);
static sdkk_error_t central_system_handle_kernel_error(sdkk_error_t error);
static sdkk_error_t central_system_load_module(const dro_module_t* module);
static sdkk_error_t central_system_unload_module(const dro_module_t* module);

// --- Global Instance Declarations ---
// These are extern declarations; their definitions are in castle_security.c
extern fairshare_warden_t Fairshare_Warden;
extern castle_security_system_t* g_security_system;

// --- Static Assertions ---
static_assert(SECURITY_HASH_SIZE == SHA256_DIGEST_LENGTH, "Hash size mismatch: SECURITY_HASH_SIZE must match SHA256_DIGEST_LENGTH");

#endif // CASTLE_SECURITY_H
