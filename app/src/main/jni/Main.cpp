/**
 * ============================================================================
 * ParallaxUrlStrengthChecking - Ultra Runtime URL Redirection & Hook Engine
 * ============================================================================
 * Developer: ParallaxDemon
 * Framework: Dobby Hook + Android NDK C++17
 * Purpose: Intercept and dynamically rewrite URLs in native libraries (libcurl)
 *          with multi-rule matching, auto dlopen interception, crash-proof
 *          memory management, and full SSL/TLS verification bypass.
 * ============================================================================
 */

#include <jni.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <regex>
#include <atomic>

#include "Dobby/dobby.h"
#include "log.h"

// ============================================================================
// [1] CONFIGURATION: TARGET LIBRARIES
// ============================================================================
// List of shared libraries whose curl calls will be intercepted.
// The engine automatically detects when these libraries load into memory.
static const std::vector<std::string> TARGET_LIBS = {
    "libil2cpp.so",    // Unity 3D / IL2CPP Games
    "libanogs.so",     // Tencent / Anti-Cheat
    "libUE4.so",       // Unreal Engine 4
    "libcurl.so",      // Standalone curl library
    "libmain.so"       // Common game entrypoint
};

// Also attempt to hook curl symbols from the global namespace (RTLD_DEFAULT)
static const bool HOOK_GLOBAL_CURL = true;

// ============================================================================
// [2] CONFIGURATION: ULTRA MULTI-URL RULES
// ============================================================================
enum class MatchType {
    EXACT,     // Match the entire URL exactly
    DOMAIN,    // Replace only the domain/host portion (keeps path & query)
    PREFIX,    // Match if URL begins with prefix
    CONTAINS,  // Replace any matching substring inside the URL
    REGEX      // Regular expression search & replace
};

struct UrlRule {
    std::string pattern;        // Search pattern / domain / regex
    std::string replacement;    // Destination URL / domain
    MatchType matchType;        // Type of matching
    bool enabled;               // Rule active status
    const char* tag;            // Identifier for logging
};

// Define all your redirection rules below. Add as many as needed!
static const std::vector<UrlRule> URL_RULES = {
    // Rule 1: Exact full URL match
    {
        "https://teamruthless.authapi.xyz/connect",
        "https://yourpanel.com/connect",
        MatchType::EXACT,
        true,
        "Auth Connect Endpoint"
    },
    // Rule 2: Domain redirection (redirects all paths on this domain)
    {
        "teamruthless.authapi.xyz",
        "yourpanel.com",
        MatchType::DOMAIN,
        true,
        "Auth Domain Swap"
    },
    // Rule 3: Substring match
    {
        "authapi.xyz",
        "yourpanel.com",
        MatchType::CONTAINS,
        true,
        "Root Domain Fallback"
    },
    // Rule 4: Custom API Gateway Prefix
    {
        "http://api.oldbackend.com/",
        "https://api.newbackend.com/",
        MatchType::PREFIX,
        false,
        "API Gateway Migration"
    }
};

// ============================================================================
// [3] CONFIGURATION: NETWORK & SECURITY CONTROLS
// ============================================================================
// Automatically upgrade any http:// requests to https://
static const bool FORCE_HTTPS = true;

// Force bypass SSL certificate and hostname verification (Fixes curl error 60 / self-signed certs)
static const bool FORCE_SSL_BYPASS = true;

// Detailed logging in Android Logcat (Tag: URL_HOOK)
static const bool VERBOSE_LOGS = true;

// ============================================================================
// [4] ORIGINAL FUNCTION POINTERS
// ============================================================================
static void* (*original_curl_easy_init)() = nullptr;
static void* (*original_curl_easy_setopt)(void*, int, ...) = nullptr;
static void* (*original_curl_easy_perform)(void*) = nullptr;
static void  (*original_curl_easy_cleanup)(void*) = nullptr;
static void* (*original_dlopen)(const char*, int) = nullptr;

// Set of already hooked function addresses to prevent re-hooking
static std::unordered_set<void*> g_hooked_addresses;
static std::mutex g_hook_mutex;

// ============================================================================
// [5] THREAD-SAFE MEMORY LIFECYCLE MANAGEMENT (CRASH-PROOF)
// ============================================================================
// Problem in naive hookers: freeing the modified URL immediately inside
// curl_easy_setopt causes a use-after-free crash during curl_easy_perform.
// Solution: We track allocated strings per curl handle and free them ONLY
// when curl_easy_cleanup() is called.
static std::unordered_map<void*, std::vector<char*>> g_handle_allocations;
static std::mutex g_alloc_mutex;

static void track_allocation(void* curl, char* ptr) {
    if (!curl || !ptr) return;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    g_handle_allocations[curl].push_back(ptr);
}

static void free_handle_allocations(void* curl) {
    if (!curl) return;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    auto it = g_handle_allocations.find(curl);
    if (it != g_handle_allocations.end()) {
        for (char* ptr : it->second) {
            if (ptr) free(ptr);
        }
        g_handle_allocations.erase(it);
    }
}

// ============================================================================
// [6] ULTRA URL REWRITING ENGINE
// ============================================================================
static std::string rewrite_url(const std::string& input_url) {
    std::string result = input_url;
    bool modified = false;

    for (const auto& rule : URL_RULES) {
        if (!rule.enabled) continue;

        switch (rule.matchType) {
            case MatchType::EXACT: {
                if (result == rule.pattern) {
                    result = rule.replacement;
                    modified = true;
                    if (VERBOSE_LOGS) {
                        LOGI("[RULE:EXACT] [%s] Exact match triggered -> %s", rule.tag, result.c_str());
                    }
                }
                break;
            }
            case MatchType::DOMAIN: {
                size_t pos = result.find(rule.pattern);
                if (pos != std::string::npos) {
                    result.replace(pos, rule.pattern.length(), rule.replacement);
                    modified = true;
                    if (VERBOSE_LOGS) {
                        LOGI("[RULE:DOMAIN] [%s] Domain replaced '%s' -> '%s'", rule.tag, rule.pattern.c_str(), rule.replacement.c_str());
                    }
                }
                break;
            }
            case MatchType::PREFIX: {
                if (result.rfind(rule.pattern, 0) == 0) {
                    result.replace(0, rule.pattern.length(), rule.replacement);
                    modified = true;
                    if (VERBOSE_LOGS) {
                        LOGI("[RULE:PREFIX] [%s] Prefix replaced -> %s", rule.tag, result.c_str());
                    }
                }
                break;
            }
            case MatchType::CONTAINS: {
                size_t pos = 0;
                bool sub_matched = false;
                while ((pos = result.find(rule.pattern, pos)) != std::string::npos) {
                    result.replace(pos, rule.pattern.length(), rule.replacement);
                    pos += rule.replacement.length();
                    sub_matched = true;
                    modified = true;
                }
                if (sub_matched && VERBOSE_LOGS) {
                    LOGI("[RULE:CONTAINS] [%s] Substring replaced -> %s", rule.tag, result.c_str());
                }
                break;
            }
            case MatchType::REGEX: {
                try {
                    std::regex re(rule.pattern);
                    if (std::regex_search(result, re)) {
                        result = std::regex_replace(result, re, rule.replacement);
                        modified = true;
                        if (VERBOSE_LOGS) {
                            LOGI("[RULE:REGEX] [%s] Regex matched -> %s", rule.tag, result.c_str());
                        }
                    }
                } catch (const std::exception& e) {
                    LOGE("[RULE:REGEX ERROR] [%s] Pattern '%s' failed: %s", rule.tag, rule.pattern.c_str(), e.what());
                }
                break;
            }
        }
    }

    // Force HTTPS if enabled
    if (FORCE_HTTPS && result.rfind("http://", 0) == 0) {
        result.replace(0, 7, "https://");
        modified = true;
        if (VERBOSE_LOGS) {
            LOGI("[UPGRADE:HTTPS] Converted http:// to https://: %s", result.c_str());
        }
    }

    if (modified) {
        LOGI("[URL HOOK SUCCESS] Old: %s", input_url.c_str());
        LOGI("[URL HOOK SUCCESS] New: %s", result.c_str());
    }

    return result;
}

// ============================================================================
// [7] HOOKED CURL IMPLEMENTATIONS
// ============================================================================
static void* hooked_curl_easy_init() {
    void* curl = original_curl_easy_init ? original_curl_easy_init() : nullptr;
    if (VERBOSE_LOGS) {
        LOGI("[CURL:INIT] Handle created: %p", curl);
    }
    return curl;
}

static void* hooked_curl_easy_setopt(void* curl, int option, ...) {
    va_list args;
    va_start(args, option);
    void* value = va_arg(args, void*);
    va_end(args);

    // CURLOPT_URL = 10002
    if (option == 10002 && value != nullptr) {
        const char* original_url = static_cast<const char*>(value);
        std::string modified_url = rewrite_url(original_url);

        if (modified_url != original_url) {
            char* safe_heap_str = strdup(modified_url.c_str());
            track_allocation(curl, safe_heap_str);
            value = safe_heap_str;
        }
    }

    // SSL Verification bypass
    if (FORCE_SSL_BYPASS) {
        // CURLOPT_SSL_VERIFYPEER = 64
        // CURLOPT_SSL_VERIFYHOST = 81
        // CURLOPT_SSL_VERIFYSTATUS = 232
        if (option == 64 || option == 81 || option == 232) {
            value = reinterpret_cast<void*>(0);
        }
    }

    if (!original_curl_easy_setopt) {
        LOGE("[CURL:ERROR] original_curl_easy_setopt is null!");
        return nullptr;
    }

    return original_curl_easy_setopt(curl, option, value);
}

static void* hooked_curl_easy_perform(void* curl) {
    if (VERBOSE_LOGS) {
        LOGI("[CURL:PERFORM] Executing request for handle: %p", curl);
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    void* result = original_curl_easy_perform ? original_curl_easy_perform(curl) : nullptr;
    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    if (VERBOSE_LOGS) {
        LOGI("[CURL:PERFORM] Completed in %lld ms (Result code: %ld)",
             static_cast<long long>(elapsed_ms),
             reinterpret_cast<intptr_t>(result));
    }

    return result;
}

static void hooked_curl_easy_cleanup(void* curl) {
    if (VERBOSE_LOGS) {
        LOGI("[CURL:CLEANUP] Cleaning up handle: %p", curl);
    }

    if (original_curl_easy_cleanup) {
        original_curl_easy_cleanup(curl);
    }

    // Safely free all transformed URL strings allocated for this handle
    free_handle_allocations(curl);
}

// ============================================================================
// [8] CORE HOOK INSTALLATION LOGIC
// ============================================================================
static bool hook_function_once(void* target_addr, void* replace_func, void** origin_func, const char* name) {
    if (!target_addr) return false;

    std::lock_guard<std::mutex> lock(g_hook_mutex);
    if (g_hooked_addresses.find(target_addr) != g_hooked_addresses.end()) {
        return true; // Already hooked
    }

    if (DobbyHook(target_addr, replace_func, origin_func) == 0) {
        g_hooked_addresses.insert(target_addr);
        LOGI("[HOOK:OK] Successfully hooked %s at %p", name, target_addr);
        return true;
    } else {
        LOGE("[HOOK:FAIL] Failed to hook %s at %p", name, target_addr);
        return false;
    }
}

static bool install_curl_hooks_from_handle(void* handle, const char* source_name) {
    if (!handle) return false;

    void* setopt_addr  = dlsym(handle, "curl_easy_setopt");
    void* init_addr    = dlsym(handle, "curl_easy_init");
    void* perform_addr = dlsym(handle, "curl_easy_perform");
    void* cleanup_addr = dlsym(handle, "curl_easy_cleanup");

    if (!setopt_addr && !init_addr && !perform_addr) {
        return false;
    }

    LOGI("[FOUND] Curl functions detected in [%s]:", source_name);

    if (setopt_addr) {
        hook_function_once(setopt_addr, (void*)hooked_curl_easy_setopt, (void**)&original_curl_easy_setopt, "curl_easy_setopt");
    }
    if (init_addr) {
        hook_function_once(init_addr, (void*)hooked_curl_easy_init, (void**)&original_curl_easy_init, "curl_easy_init");
    }
    if (perform_addr) {
        hook_function_once(perform_addr, (void*)hooked_curl_easy_perform, (void**)&original_curl_easy_perform, "curl_easy_perform");
    }
    if (cleanup_addr) {
        hook_function_once(cleanup_addr, (void*)hooked_curl_easy_cleanup, (void**)&original_curl_easy_cleanup, "curl_easy_cleanup");
    }

    return true;
}

static bool check_and_hook_library(const std::string& lib_name) {
    // 1. Try RTLD_NOLOAD first to check if already in memory without loading
    void* handle = dlopen(lib_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        // 2. Try loading if safe
        handle = dlopen(lib_name.c_str(), RTLD_NOW);
    }

    if (handle) {
        return install_curl_hooks_from_handle(handle, lib_name.c_str());
    }
    return false;
}

// ============================================================================
// [9] DYNAMIC DLOPEN INTERCEPTOR (INSTANT DETECTION ON LOAD)
// ============================================================================
static void* hooked_dlopen(const char* filename, int flags) {
    void* handle = original_dlopen ? original_dlopen(filename, flags) : nullptr;

    if (filename && handle) {
        for (const auto& target : TARGET_LIBS) {
            if (strstr(filename, target.c_str()) != nullptr) {
                LOGI("[DLOPEN:DETECTED] Target library loaded: %s (%p)", filename, handle);
                install_curl_hooks_from_handle(handle, filename);
                break;
            }
        }
    }

    return handle;
}

static void install_dlopen_hook() {
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (dlopen_addr) {
        hook_function_once(dlopen_addr, (void*)hooked_dlopen, (void**)&original_dlopen, "dlopen");
    }
}

// ============================================================================
// [10] BACKGROUND WATCHER THREAD (FAIL-SAFE MAP SCANNER)
// ============================================================================
// Runs in the background to monitor /proc/self/maps in case libraries are
// loaded by an internal packer, custom linker, or JNI without standard dlopen.
static void* background_watcher_thread(void*) {
    LOGI("[WATCHER] Background library monitor thread started");

    int scan_count = 0;
    while (scan_count < 120) { // Scan for up to 60 seconds (120 * 500ms)
        usleep(500 * 1000);   // 500ms sleep
        scan_count++;

        FILE* fp = fopen("/proc/self/maps", "re");
        if (!fp) continue;

        char line[512];
        std::unordered_set<std::string> found_libs;

        while (fgets(line, sizeof(line), fp)) {
            for (const auto& target : TARGET_LIBS) {
                if (strstr(line, target.c_str()) != nullptr) {
                    found_libs.insert(target);
                }
            }
        }
        fclose(fp);

        for (const auto& lib : found_libs) {
            check_and_hook_library(lib);
        }

        // If all curl hooks are installed, we can slow down or exit watcher
        if (original_curl_easy_setopt != nullptr) {
            LOGI("[WATCHER] All core hooks installed successfully! Watcher entering idle mode.");
            break;
        }
    }

    return nullptr;
}

// ============================================================================
// [11] GLOBAL INITIALIZATION ROUTINE
// ============================================================================
static void init_engine() {
    static std::atomic<bool> initialized(false);
    if (initialized.exchange(true)) return;

    LOGI("=================================================");
    LOGI(" PARALLAX ULTRA RUNTIME URL REDIRECTOR INITIALIZED");
    LOGI(" Developer: ParallaxDemon");
    LOGI(" Version: 2.0 (Ultra Level)");
    LOGI("=================================================");

    // 1. Hook dlopen to catch libraries when loaded
    install_dlopen_hook();

    // 2. Try global namespace hooks immediately if enabled
    if (HOOK_GLOBAL_CURL) {
        install_curl_hooks_from_handle(RTLD_DEFAULT, "Global/RTLD_DEFAULT");
    }

    // 3. Check already loaded target libraries
    for (const auto& lib : TARGET_LIBS) {
        check_and_hook_library(lib);
    }

    // 4. Start background watcher thread as fail-safe
    pthread_t thread;
    pthread_create(&thread, nullptr, background_watcher_thread, nullptr);
    pthread_detach(thread);
}

// Automatically triggered when .so is loaded into process memory
__attribute__((constructor)) static void on_library_load() {
    init_engine();
}

// Standard JNI entrypoint
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("[JNI] JNI_OnLoad called");
    init_engine();
    return JNI_VERSION_1_6;
}

// Destructor
__attribute__((destructor)) static void on_library_unload() {
    LOGI("[CLEANUP] Library unloading");
}
