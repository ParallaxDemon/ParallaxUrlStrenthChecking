/**
 * ============================================================================
 * ParallaxUrlStrengthChecking - Ultra Runtime URL Redirection & Hook Engine
 * ============================================================================
 * Developer: ParallaxDemon
 * Multi-Engine: Dobby Hook + And64InlineHook (Rprop) + Memory Scanner + DNS Interceptor
 * Features:
 *   [Layer 1] DNS Interception: Hooks getaddrinfo / gethostbyname to redirect any native socket
 *   [Layer 2] cURL API Hooking: Hooks curl_easy_setopt, curl_url_set, with full SSL/TLS bypass
 *   [Layer 3] Direct Memory Scanner: In-memory byte scanning & mprotect hot-patching
 *   [Layer 4] Dual Hooking Engines: Dobby + And64InlineHook hybrid fallback
 *   [Layer 5] Hard-coded rules only: all URLs live in this C++ file (no config file / dependency)
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
#include <netdb.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <regex>
#include <atomic>

#include "Dobby/dobby.h"
#if defined(__aarch64__)
#include "And64InlineHook/And64InlineHook.hpp"
#endif
#include "log.h"

// ============================================================================
// [1] CONFIGURATION: TARGET LIBRARIES
// ============================================================================
// Libraries to monitor, hook, and memory-patch
static std::vector<std::string> TARGET_LIBS = {
    "libDARK.so",      // Target library carrying the taitogaming auth URL (XOR + code-built)
    "libil2cpp.so",    // Unity 3D / IL2CPP Games
    "libanogs.so",     // Anti-Cheat / Tencent
    "libUE4.so",       // Unreal Engine 4
    "libcurl.so",      // Standalone cURL
    "libmain.so"       // Common game loader
};

// Also hook curl from global symbol space (RTLD_DEFAULT)
static bool HOOK_GLOBAL_CURL = true;

// ============================================================================
// [2] CONFIGURATION: ULTRA MULTI-URL RULES
// ============================================================================
enum class MatchType {
    EXACT,     // Match the entire URL exactly
    DOMAIN,    // Replace only the domain/host (keeps path & query intact)
    PREFIX,    // Match if URL begins with prefix
    CONTAINS,  // Replace any matching substring inside the URL
    REGEX      // Regular expression search & replace
};

struct UrlRule {
    std::string pattern;        // Search pattern / domain / regex
    std::string replacement;    // Destination URL / domain
    MatchType matchType;        // Type of matching
    bool enabled;               // Rule active status
    std::string tag;            // Identifier for logging
};

// Hard-coded rules — the ONLY source of URLs in this build. No JSON/config file is read.
static std::vector<UrlRule> URL_RULES = {
    // Rule 0: Requested redirect - taitogaming auth endpoint -> darkdevel panel
    {
        "https://taitogaming.authapi.xyz/server",
        "https://darkdevel.parallaxserver.online/connect",
        MatchType::EXACT,
        true,
        "Taito -> Darkdevel Auth Endpoint"
    },
    // Rule 0b: Domain fallback for any other path on the old host
    {
        "taitogaming.authapi.xyz",
        "darkdevel.parallaxserver.online",
        MatchType::DOMAIN,
        true,
        "Taito -> Darkdevel Domain Swap"
    },
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

static std::mutex g_rules_mutex;

// ============================================================================
// [3] GLOBAL SETTINGS
// ============================================================================
static bool FORCE_HTTPS = true;           // Auto convert http:// to https://
static bool FORCE_SSL_BYPASS = true;      // Bypass SSL certificate and hostname verification
static bool VERBOSE_LOGS = true;          // Detailed Logcat output (Tag: URL_HOOK)
static bool ENABLE_DNS_HOOK = true;       // Intercept getaddrinfo / gethostbyname
static bool ENABLE_MEMORY_PATCH = true;   // Direct in-memory byte scanner & patcher

// ============================================================================
// [4] ORIGINAL FUNCTION POINTERS
// ============================================================================
static void* (*original_curl_easy_init)() = nullptr;
static void* (*original_curl_easy_setopt)(void*, int, ...) = nullptr;
// libDARK.so statically links curl; its internal setopt needs a separate trampoline.
static void* (*original_libdark_curl_easy_setopt)(void*, int, ...) = nullptr;
static void* (*original_curl_easy_perform)(void*) = nullptr;
static void  (*original_curl_easy_cleanup)(void*) = nullptr;
static int   (*original_curl_url_set)(void*, int, const char*, unsigned int) = nullptr;

static void* (*original_dlopen)(const char*, int) = nullptr;
static int   (*original_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = nullptr;
static struct hostent* (*original_gethostbyname)(const char*) = nullptr;

static std::unordered_set<void*> g_hooked_addresses;
static std::mutex g_hook_mutex;

// ============================================================================
// [5] DUAL HOOKING ENGINE (DOBBY + AND64INLINEHOOK HYBRID)
// ============================================================================
enum class HookEngine {
    AUTO_HYBRID,    // Try Dobby first; on ARM64 fallback to And64InlineHook
    DOBBY_ONLY,     // Dobby Hook exclusively
    AND64_ONLY      // And64InlineHook exclusively
};

static HookEngine G_HOOK_ENGINE = HookEngine::AUTO_HYBRID;

bool UnifiedHook(void* target, void* replace, void** origin, const char* name) {
    if (!target || !replace) return false;

    std::lock_guard<std::mutex> lock(g_hook_mutex);
    if (g_hooked_addresses.find(target) != g_hooked_addresses.end()) {
        return true; // Already hooked
    }

    bool success = false;

    // Method 1: Dobby Hook
    if (G_HOOK_ENGINE == HookEngine::AUTO_HYBRID || G_HOOK_ENGINE == HookEngine::DOBBY_ONLY) {
        if (DobbyHook(target, replace, origin) == 0) {
            success = true;
            LOGI("[HOOK:DOBBY] ✓ Hooked %s at %p", name, target);
        } else {
            LOGW("[HOOK:DOBBY] Dobby failed for %s at %p, trying fallback...", name, target);
        }
    }

    // Method 2: And64InlineHook (Rprop) Fallback on ARM64
#if defined(__aarch64__)
    if (!success && (G_HOOK_ENGINE == HookEngine::AUTO_HYBRID || G_HOOK_ENGINE == HookEngine::AND64_ONLY)) {
        A64HookFunction(target, replace, origin);
        success = true;
        LOGI("[HOOK:AND64] ✓ Hooked %s with And64InlineHook at %p", name, target);
    }
#endif

    if (success) {
        g_hooked_addresses.insert(target);
    } else {
        LOGE("[HOOK:FAIL] All hook engines failed for %s at %p", name, target);
    }

    return success;
}

// Hook raw memory offset (RVA) in a library (e.g., base + 0x123456)
uintptr_t get_library_base(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "re");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) != nullptr) {
            base = strtoul(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

bool HookByRVA(const char* lib_name, uintptr_t offset, void* replace, void** origin, const char* name) {
    uintptr_t base = get_library_base(lib_name);
    if (!base) {
        LOGE("[RVA:ERROR] Base address for %s not found", lib_name);
        return false;
    }
    void* target = reinterpret_cast<void*>(base + offset);
    LOGI("[RVA:HOOK] Hooking %s at %s+0x%lx (%p)", name, lib_name, (unsigned long)offset, target);
    return UnifiedHook(target, replace, origin, name);
}

// ============================================================================
// [6] CRASH-PROOF MEMORY LIFECYCLE MANAGEMENT
// ============================================================================
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
// [7] DYNAMIC URL REWRITING ENGINE
// ============================================================================
static std::string rewrite_url(const std::string& input_url) {
    std::lock_guard<std::mutex> lock(g_rules_mutex);
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
                        LOGI("[RULE:EXACT] [%s] URL match -> %s", rule.tag.c_str(), result.c_str());
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
                        LOGI("[RULE:DOMAIN] [%s] Domain '%s' -> '%s'", rule.tag.c_str(), rule.pattern.c_str(), rule.replacement.c_str());
                    }
                }
                break;
            }
            case MatchType::PREFIX: {
                if (result.rfind(rule.pattern, 0) == 0) {
                    result.replace(0, rule.pattern.length(), rule.replacement);
                    modified = true;
                    if (VERBOSE_LOGS) {
                        LOGI("[RULE:PREFIX] [%s] Prefix replaced -> %s", rule.tag.c_str(), result.c_str());
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
                    LOGI("[RULE:CONTAINS] [%s] Substring swapped -> %s", rule.tag.c_str(), result.c_str());
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
                            LOGI("[RULE:REGEX] [%s] Regex match -> %s", rule.tag.c_str(), result.c_str());
                        }
                    }
                } catch (const std::exception& e) {
                    LOGE("[RULE:REGEX ERROR] [%s] %s: %s", rule.tag.c_str(), rule.pattern.c_str(), e.what());
                }
                break;
            }
        }
    }

    if (FORCE_HTTPS && result.rfind("http://", 0) == 0) {
        result.replace(0, 7, "https://");
        modified = true;
        if (VERBOSE_LOGS) {
            LOGI("[UPGRADE:HTTPS] http:// -> https://: %s", result.c_str());
        }
    }

    if (modified) {
        LOGI("[URL HOOKED] %s -> %s", input_url.c_str(), result.c_str());
    }

    return result;
}

// Rewrites raw domain/hostname for DNS interceptor
static std::string rewrite_host(const std::string& input_host) {
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    for (const auto& rule : URL_RULES) {
        if (!rule.enabled) continue;
        if (rule.matchType == MatchType::DOMAIN || rule.matchType == MatchType::CONTAINS) {
            size_t pos = input_host.find(rule.pattern);
            if (pos != std::string::npos) {
                std::string res = input_host;
                res.replace(pos, rule.pattern.length(), rule.replacement);
                return res;
            }
        } else if (rule.matchType == MatchType::EXACT) {
            if (input_host == rule.pattern) {
                return rule.replacement;
            }
        }
    }
    return input_host;
}

// ============================================================================
// [8] LAYER 1: DNS / HOSTNAME INTERCEPTION (libc)
// ============================================================================
static int hooked_getaddrinfo(const char* node, const char* service,
                             const struct addrinfo* hints, struct addrinfo** res) {
    if (node != nullptr) {
        std::string host(node);
        std::string redirected = rewrite_host(host);
        if (redirected != host) {
            LOGI("[DNS:GETADDRINFO] Intercepted DNS: '%s' -> '%s'", host.c_str(), redirected.c_str());
            return original_getaddrinfo ? original_getaddrinfo(redirected.c_str(), service, hints, res) : EAI_FAIL;
        }
    }
    return original_getaddrinfo ? original_getaddrinfo(node, service, hints, res) : EAI_FAIL;
}

static struct hostent* hooked_gethostbyname(const char* name) {
    if (name != nullptr) {
        std::string host(name);
        std::string redirected = rewrite_host(host);
        if (redirected != host) {
            LOGI("[DNS:GETHOSTBYNAME] Intercepted DNS: '%s' -> '%s'", host.c_str(), redirected.c_str());
            return original_gethostbyname ? original_gethostbyname(redirected.c_str()) : nullptr;
        }
    }
    return original_gethostbyname ? original_gethostbyname(name) : nullptr;
}

static void install_dns_hooks() {
    if (!ENABLE_DNS_HOOK) return;

    void* addrinfo_ptr = dlsym(RTLD_DEFAULT, "getaddrinfo");
    if (addrinfo_ptr) {
        UnifiedHook(addrinfo_ptr, (void*)hooked_getaddrinfo, (void**)&original_getaddrinfo, "getaddrinfo");
    }

    void* hostbyname_ptr = dlsym(RTLD_DEFAULT, "gethostbyname");
    if (hostbyname_ptr) {
        UnifiedHook(hostbyname_ptr, (void*)hooked_gethostbyname, (void**)&original_gethostbyname, "gethostbyname");
    }
}

// ============================================================================
// [9] LAYER 2: COMPREHENSIVE CURL API HOOKS
// ============================================================================
static void* hooked_curl_easy_init() {
    void* curl = original_curl_easy_init ? original_curl_easy_init() : nullptr;
    if (VERBOSE_LOGS) {
        LOGI("[CURL:INIT] Handle created: %p", curl);
    }
    return curl;
}

static void* rewrite_setopt_value(void* curl, int option, void* value) {
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
        // CURLOPT_CAINFO = 10065
        // CURLOPT_CAPATH = 10097
        if (option == 64 || option == 81 || option == 232) {
            value = reinterpret_cast<void*>(0);
        } else if (option == 10065 || option == 10097) {
            value = nullptr;
        }
    }

    return value;
}

static void* hooked_curl_easy_setopt(void* curl, int option, ...) {
    va_list args;
    va_start(args, option);
    void* value = va_arg(args, void*);
    va_end(args);

    value = rewrite_setopt_value(curl, option, value);

    if (!original_curl_easy_setopt) return nullptr;
    return original_curl_easy_setopt(curl, option, value);
}

// libDARK.so statically links its own curl copy, so its internal setopt is
// hooked by RVA and routed through this dedicated trampoline.
static void* hooked_libdark_curl_easy_setopt(void* curl, int option, ...) {
    va_list args;
    va_start(args, option);
    void* value = va_arg(args, void*);
    va_end(args);

    value = rewrite_setopt_value(curl, option, value);

    if (!original_libdark_curl_easy_setopt) return nullptr;
    return original_libdark_curl_easy_setopt(curl, option, value);
}

// Modern libcurl URL API (curl_url_set)
static int hooked_curl_url_set(void* u, int what, const char* part, unsigned int flags) {
    if (part != nullptr) {
        // CURLUPART_URL = 1, CURLUPART_HOST = 3
        if (what == 1) {
            std::string modified = rewrite_url(part);
            return original_curl_url_set ? original_curl_url_set(u, what, modified.c_str(), flags) : 0;
        } else if (what == 3) {
            std::string modified = rewrite_host(part);
            return original_curl_url_set ? original_curl_url_set(u, what, modified.c_str(), flags) : 0;
        }
    }
    return original_curl_url_set ? original_curl_url_set(u, what, part, flags) : 0;
}

static void* hooked_curl_easy_perform(void* curl) {
    if (VERBOSE_LOGS) {
        LOGI("[CURL:PERFORM] Starting request on handle: %p", curl);
    }

    auto start = std::chrono::high_resolution_clock::now();
    void* result = original_curl_easy_perform ? original_curl_easy_perform(curl) : nullptr;
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start).count();

    if (VERBOSE_LOGS) {
        LOGI("[CURL:PERFORM] Finished in %lld ms (code: %ld)",
             static_cast<long long>(elapsed), reinterpret_cast<intptr_t>(result));
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

    free_handle_allocations(curl);
}

// ============================================================================
// [9b] LAYER 2B: libDARK.so STATIC-CURL RVA HOOK
// ============================================================================
// The taitogaming URL in libDARK.so is XOR-obfuscated and finished from code
// immediates, and libcurl is linked statically (no exported curl_easy_setopt).
// On the known build, the call at libDARK+0xd8168 reaches the internal setopt
// at libDARK+0x126618. Verify the XOR blob before hooking so a different build
// is never patched at a wrong offset.
static constexpr uintptr_t LIBDARK_SETREQ_RVA      = 0x126618;
static constexpr uintptr_t LIBDARK_BLOB_OFFSET     = 0x305e40;
static constexpr unsigned char LIBDARK_XOR_KEY     = 0x2E;
static const char LIBDARK_OLD_URL[] = "https://taitogaming.authapi.xyz/server";

static std::string get_library_path(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "re");
    if (!fp) return "";

    char line[512];
    std::string path;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) == nullptr) continue;

        uintptr_t start = 0, end = 0, offset = 0;
        unsigned long inode = 0;
        char perms[8] = {0};
        int path_index = 0;

        // start-end perms offset dev inode pathname
        if (sscanf(line, "%lx-%lx %7s %lx %*s %lu %n",
                   &start, &end, perms, &offset, &inode, &path_index) >= 5 &&
            path_index > 0) {
            path = line + path_index;
            size_t first = path.find_first_not_of(" \t");
            path = (first == std::string::npos) ? "" : path.substr(first);
            while (!path.empty() &&
                   (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
                path.pop_back();
            }
        }
        break;
    }
    fclose(fp);
    return path;
}

static bool verify_libdark_build(const std::string& path) {
    if (path.empty()) return false;

    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;

    if (fseek(fp, static_cast<long>(LIBDARK_BLOB_OFFSET), SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }

    unsigned char expected[16];
    for (size_t i = 0; i < sizeof(expected); ++i) {
        expected[i] = static_cast<unsigned char>(LIBDARK_OLD_URL[i]) ^ LIBDARK_XOR_KEY;
    }

    unsigned char actual[16];
    size_t read_bytes = fread(actual, 1, sizeof(actual), fp);
    fclose(fp);

    return read_bytes == sizeof(actual) && memcmp(actual, expected, sizeof(expected)) == 0;
}

static void install_libdark_rva_hooks() {
    static std::atomic<bool> attempted(false);

    uintptr_t base = get_library_base("libDARK.so");
    if (!base) {
        // Not loaded yet; the dlopen/watcher paths will retry.
        attempted.store(false);
        return;
    }
    if (attempted.exchange(true)) return;

    std::string path = get_library_path("libDARK.so");
    if (!verify_libdark_build(path)) {
        LOGW("[RVA:LIBDARK] XOR signature not found in %s; skip RVA curl hook",
             path.empty() ? "libDARK.so" : path.c_str());
        return;
    }

    LOGI("[RVA:LIBDARK] XOR blob verified at +0x%lx; hook internal curl_easy_setopt at +0x%lx",
         static_cast<unsigned long>(LIBDARK_BLOB_OFFSET),
         static_cast<unsigned long>(LIBDARK_SETREQ_RVA));

    HookByRVA("libDARK.so", LIBDARK_SETREQ_RVA,
              reinterpret_cast<void*>(hooked_libdark_curl_easy_setopt),
              reinterpret_cast<void**>(&original_libdark_curl_easy_setopt),
              "libDARK curl_easy_setopt");
}

// ============================================================================
// [10] LAYER 3: DIRECT IN-MEMORY STRING SCANNER & HOT-PATCHER
// ============================================================================
// Scans mapped memory pages of a library for target URL bytes and patches them
// using mprotect. Useful when functions are stripped or statically inlined!
static void scan_and_patch_memory(const char* lib_name) {
    if (!ENABLE_MEMORY_PATCH) return;

    FILE* fp = fopen("/proc/self/maps", "re");
    if (!fp) return;

    struct Segment {
        uintptr_t start;
        uintptr_t end;
        int prot;
    };
    std::vector<Segment> segments;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) == nullptr) continue;

        uintptr_t start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue;

        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        segments.push_back({start, end, prot});
    }
    fclose(fp);

    if (segments.empty()) return;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    long page_size = sysconf(_SC_PAGESIZE);

    for (const auto& seg : segments) {
        for (const auto& rule : URL_RULES) {
            if (!rule.enabled) continue;
            if (rule.pattern.empty() || rule.replacement.empty()) continue;

            const char* needle = rule.pattern.c_str();
            size_t needle_len  = rule.pattern.length();
            const char* repl   = rule.replacement.c_str();
            size_t repl_len    = rule.replacement.length();

            // Search bytes in segment
            const char* current = reinterpret_cast<const char*>(seg.start);
            const char* end_ptr = reinterpret_cast<const char*>(seg.end - needle_len);

            while (current <= end_ptr) {
                if (memcmp(current, needle, needle_len) == 0) {
                    if (repl_len > needle_len) {
                        LOGW("[MEM:PATCH] Replacement '%s' is longer than pattern (%zu > %zu), skipping in-place patch",
                             repl, repl_len, needle_len);
                        current += needle_len;
                        continue;
                    }

                    uintptr_t match_addr = reinterpret_cast<uintptr_t>(current);
                    uintptr_t page_start = match_addr & ~(page_size - 1);
                    size_t patch_pages   = page_size * 2;

                    // Grant write permission only when an actual in-place patch fits.
                    if (mprotect(reinterpret_cast<void*>(page_start), patch_pages,
                                 PROT_READ | PROT_WRITE) == 0) {
                        memcpy(reinterpret_cast<void*>(match_addr), repl, repl_len);
                        if (repl_len < needle_len) {
                            memset(reinterpret_cast<void*>(match_addr + repl_len), 0,
                                   needle_len - repl_len);
                        }
                        LOGI("[MEM:PATCH] ✓ Hot-patched '%s' -> '%s' at %p in %s",
                             needle, repl, reinterpret_cast<void*>(match_addr), lib_name);

                        __builtin___clear_cache(reinterpret_cast<char*>(page_start),
                                               reinterpret_cast<char*>(page_start + patch_pages));
                        // Restore the ORIGINAL protections (including PROT_EXEC) — restoring
                        // only PROT_READ here would turn executable pages into non-executable
                        // ones and crash the app.
                        mprotect(reinterpret_cast<void*>(page_start), patch_pages, seg.prot);
                    } else {
                        LOGE("[MEM:PATCH] mprotect failed at %p", reinterpret_cast<void*>(page_start));
                    }
                    current += needle_len;
                } else {
                    current++;
                }
            }
        }
    }
}

// ============================================================================
// [11] LAYER 4: HOOK INSTALLATION DISPATCHER
// ============================================================================
static bool install_curl_hooks_from_handle(void* handle, const char* source_name) {
    if (!handle) return false;

    void* setopt_addr  = dlsym(handle, "curl_easy_setopt");
    void* init_addr    = dlsym(handle, "curl_easy_init");
    void* perform_addr = dlsym(handle, "curl_easy_perform");
    void* cleanup_addr = dlsym(handle, "curl_easy_cleanup");
    void* url_set_addr = dlsym(handle, "curl_url_set");

    if (!setopt_addr && !init_addr && !perform_addr && !url_set_addr) {
        return false;
    }

    LOGI("[FOUND] cURL symbols detected in [%s]:", source_name);

    if (setopt_addr) {
        UnifiedHook(setopt_addr, (void*)hooked_curl_easy_setopt, (void**)&original_curl_easy_setopt, "curl_easy_setopt");
    }
    if (init_addr) {
        UnifiedHook(init_addr, (void*)hooked_curl_easy_init, (void**)&original_curl_easy_init, "curl_easy_init");
    }
    if (perform_addr) {
        UnifiedHook(perform_addr, (void*)hooked_curl_easy_perform, (void**)&original_curl_easy_perform, "curl_easy_perform");
    }
    if (cleanup_addr) {
        UnifiedHook(cleanup_addr, (void*)hooked_curl_easy_cleanup, (void**)&original_curl_easy_cleanup, "curl_easy_cleanup");
    }
    if (url_set_addr) {
        UnifiedHook(url_set_addr, (void*)hooked_curl_url_set, (void**)&original_curl_url_set, "curl_url_set");
    }

    return true;
}

static bool check_and_hook_library(const std::string& lib_name) {
    // 1. Try RTLD_NOLOAD first
    void* handle = dlopen(lib_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(lib_name.c_str(), RTLD_NOW);
    }

    bool hooked = false;
    if (handle) {
        hooked = install_curl_hooks_from_handle(handle, lib_name.c_str());
    }

    // libDARK.so has a statically linked curl; hook its internal setopt by RVA.
    if (lib_name.find("libDARK.so") != std::string::npos) {
        install_libdark_rva_hooks();
    }

    // 2. Perform direct in-memory byte patch on the library
    scan_and_patch_memory(lib_name.c_str());

    return hooked;
}

// ============================================================================
// [12] DLOPEN INTERCEPTOR & WATCHER THREAD
// ============================================================================
static void* hooked_dlopen(const char* filename, int flags) {
    void* handle = original_dlopen ? original_dlopen(filename, flags) : nullptr;

    if (filename && handle) {
        for (const auto& target : TARGET_LIBS) {
            if (strstr(filename, target.c_str()) != nullptr) {
                LOGI("[DLOPEN:DETECTED] Loaded: %s (%p)", filename, handle);
                install_curl_hooks_from_handle(handle, filename);
                if (target == "libDARK.so") {
                    install_libdark_rva_hooks();
                }
                scan_and_patch_memory(target.c_str());
                break;
            }
        }
    }

    return handle;
}

static void install_dlopen_hook() {
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (dlopen_addr) {
        UnifiedHook(dlopen_addr, (void*)hooked_dlopen, (void**)&original_dlopen, "dlopen");
    }
}

// Background watcher checks /proc/self/maps periodically
static void* background_watcher_thread(void*) {
    LOGI("[WATCHER] Background engine monitor started");

    int scan_count = 0;
    while (scan_count < 150) { // Scan for up to 75 seconds
        usleep(500 * 1000);   // 500ms
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

        if (original_curl_easy_setopt != nullptr) {
            // Found core curl, continue light monitoring
            usleep(2000 * 1000);
        }
    }

    return nullptr;
}

// ============================================================================
// [13] NO EXTERNAL CONFIG — URLs ARE HARD-CODED IN C++ ONLY
// ============================================================================
// There is intentionally no file/JSON/env/network config loader here. Every
// redirect rule, target library, and setting is defined above in this file.

// ============================================================================
// [14] GLOBAL INITIALIZATION
// ============================================================================
static void init_engine() {
    static std::atomic<bool> initialized(false);
    if (initialized.exchange(true)) return;

    LOGI("=================================================");
    LOGI(" PARALLAX ULTRA URL HOOK ENGINE (MAXIMUM EDITION)");
    LOGI(" Developer: ParallaxDemon");
    LOGI(" Engines: Dobby + And64InlineHook + DNS + Memory");
    LOGI("=================================================");

    // 1. Install libc DNS hooks (getaddrinfo, gethostbyname)
    install_dns_hooks();

    // 2. Hook dlopen to intercept newly loaded libraries
    install_dlopen_hook();

    // 3. Hook global curl symbols immediately
    if (HOOK_GLOBAL_CURL) {
        install_curl_hooks_from_handle(RTLD_DEFAULT, "Global/RTLD_DEFAULT");
    }

    // 4. Check and patch currently loaded target libraries
    for (const auto& lib : TARGET_LIBS) {
        check_and_hook_library(lib);
    }

    // 5. Launch background watcher thread
    pthread_t thread;
    pthread_create(&thread, nullptr, background_watcher_thread, nullptr);
    pthread_detach(thread);
}

__attribute__((constructor)) static void on_library_load() {
    init_engine();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("[JNI] JNI_OnLoad called");
    init_engine();
    return JNI_VERSION_1_6;
}

__attribute__((destructor)) static void on_library_unload() {
    LOGI("[CLEANUP] Engine unloading");
}
