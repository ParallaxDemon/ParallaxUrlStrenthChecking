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
 *   [Hardening] Page-safe mprotect, NOLOAD-only scans, dlopen fallback, retry-safe RVA hooks
 *   [Early load] Ships as libPHOENIX.so; starts from JNI_OnLoad before libDARK.so and
 *                forwards to the real libPHOENIX_orig.so so app behaviour is preserved.
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
#include <sys/system_properties.h>
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
    // Same endpoint with query parameters (key=..., device=..., etc.)
    {
        "https://taitogaming.authapi.xyz/server",
        "https://darkdevel.parallaxserver.online/connect",
        MatchType::PREFIX,
        true,
        "Taito -> Darkdevel Auth Endpoint (with query)"
    },
    // Last-resort host/path swap if the URL is assembled differently
    {
        "authapi.xyz/server",
        "darkdevel.parallaxserver.online/connect",
        MatchType::CONTAINS,
        true,
        "Taito auth host -> Darkdevel (contains)"
    },
    // Rule 0b: Domain fallback for any other path on the old host
    {
        "taitogaming.authapi.xyz",
        "darkdevel.parallaxserver.online",
        MatchType::DOMAIN,
        true,
        "Taito -> Darkdevel Domain Swap"
    },
    // Rule 1: Exact full URL match -> darkdevel panel
    {
        "https://teamruthless.authapi.xyz/connect",
        "https://darkdevel.parallaxserver.online/connect",
        MatchType::EXACT,
        true,
        "Auth Connect Endpoint"
    },
    // Rule 2: Domain redirection (redirects all paths on this domain)
    {
        "teamruthless.authapi.xyz",
        "darkdevel.parallaxserver.online",
        MatchType::DOMAIN,
        true,
        "Auth Domain Swap"
    },
    // Rule 3: Substring match -> darkdevel panel host
    {
        "authapi.xyz",
        "darkdevel.parallaxserver.online",
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
static bool VERBOSE_LOGS = false;         // Detailed Logcat output (Tag: URL_HOOK)
static bool ENABLE_DNS_HOOK = true;       // Intercept getaddrinfo / gethostbyname
// Disabled: every configured replacement is longer than its obfuscated
// pattern, so the scanner never changed a byte. Worse, libanogs.so is loaded
// and unloaded repeatedly while the scanner walks a /proc/self/maps snapshot;
// scanning a segment that has since been unmapped caused SIGSEGV ~1.7s after
// launch. URL rewriting is handled by the hooks below instead.
static bool ENABLE_MEMORY_PATCH = false;  // Direct in-memory byte scanner & patcher

// Diagnostic switch (debug builds only): when set, install ONLY the libDARK
// throw-branch patch and skip all function hooks. Used to determine whether a
// late anti-tamper SIGSEGV comes from our hooks or from the mod itself.
static bool minimal_diagnostic_mode() {
    static int cached = -1;
    if (cached < 0) {
        char value[8] = {0};
        cached = __system_property_get("debug.phoenix.minimal", value) > 0 &&
                 value[0] == '1';
    }
    return cached != 0;
}

// ============================================================================
// [4] ORIGINAL FUNCTION POINTERS
// ============================================================================
static void* (*original_curl_easy_init)() = nullptr;
static void* (*original_curl_easy_setopt)(void*, int, ...) = nullptr;
// libDARK.so statically links curl; its internal setopt needs a separate trampoline.
static void* (*original_libdark_curl_easy_setopt)(void*, int, ...) = nullptr;
// libDARK+0xe8734 parses the HTTP response body with nlohmann::json.
static void* (*original_libdark_json_parse)(void*, int, void*) = nullptr;
static void* (*original_libdark_parse)(void*, void*) = nullptr;
static void* (*original_curl_easy_perform)(void*) = nullptr;
static void  (*original_curl_easy_cleanup)(void*) = nullptr;
static int   (*original_curl_url_set)(void*, int, const char*, unsigned int) = nullptr;

static void* (*original_dlopen)(const char*, int) = nullptr;
static void* (*original_android_dlopen_ext)(const char*, int, const void*) = nullptr;
static int   (*original_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = nullptr;
static struct hostent* (*original_gethostbyname)(const char*) = nullptr;

// POD-only tracking: no std::unordered_set here. A loader-time constructor used
// to insert into a global unordered_set before its bucket state was ready,
// which could throw std::overflow_error(__next_prime overflow) and abort the
// process inside System.loadLibrary(). A fixed array has no dynamic
// initialization and cannot rehash/throw.
static constexpr size_t MAX_TRACKED_HOOKS = 256;
static void* g_hooked_addresses[MAX_TRACKED_HOOKS] = {};
static size_t g_hooked_count = 0;
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
    if (target == replace) return true; // Never hook our own trampoline.

    std::lock_guard<std::mutex> lock(g_hook_mutex);
    for (size_t i = 0; i < g_hooked_count; ++i) {
        if (g_hooked_addresses[i] == target) {
            return true; // Already hooked
        }
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
        if (g_hooked_count < MAX_TRACKED_HOOKS) {
            g_hooked_addresses[g_hooked_count++] = target;
        } else {
            LOGW("[HOOK:WARN] Hook tracking full (%zu), still hooked %s", g_hooked_count, name);
        }
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
// POD-only allocation tracking (same rationale as hook tracking above).
struct TrackedAllocation {
    void* curl;
    char* ptr;
};
static constexpr size_t MAX_TRACKED_ALLOCATIONS = 256;
static TrackedAllocation g_handle_allocations[MAX_TRACKED_ALLOCATIONS] = {};
static size_t g_allocation_count = 0;
static std::mutex g_alloc_mutex;

static void track_allocation(void* curl, char* ptr) {
    if (!curl || !ptr) return;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    if (g_allocation_count < MAX_TRACKED_ALLOCATIONS) {
        g_handle_allocations[g_allocation_count].curl = curl;
        g_handle_allocations[g_allocation_count].ptr = ptr;
        ++g_allocation_count;
    } else {
        LOGW("[ALLOC] Tracking table full, freeing untracked buffer");
        free(ptr);
    }
}

static void free_handle_allocations(void* curl) {
    if (!curl) return;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    size_t kept = 0;
    for (size_t i = 0; i < g_allocation_count; ++i) {
        if (g_handle_allocations[i].curl == curl) {
            if (g_handle_allocations[i].ptr) free(g_handle_allocations[i].ptr);
            continue;
        }
        if (kept != i) g_handle_allocations[kept] = g_handle_allocations[i];
        ++kept;
    }
    g_allocation_count = kept;
}

// ============================================================================
// [7] DYNAMIC URL REWRITING ENGINE
// ============================================================================
static std::string rewrite_url(const std::string& input_url) {
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    std::string result = input_url;
    bool modified = false;

    for (const auto& rule : URL_RULES) {
        if (!rule.enabled || rule.pattern.empty()) continue;

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
        if (!rule.enabled || rule.pattern.empty()) continue;
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

    LOGI("[LIBCURL:ENTER] option=%d value=%p", option, value);

    // Diagnostic: this is the exact call libDARK uses to set its auth URL.
    // CURLOPT_URL is 10002. Log every URL call even when no rule matches so we
    // can prove whether the static-curl RVA hook fired before the JSON parse.
    if (option == 10002 && value != nullptr) {
        LOGI("[CURL:URL] libDARK CURLOPT_URL = '%.192s'", static_cast<const char*>(value));
    }

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

// libDARK+0xe8734 receives (owner, flag, std::string* body) and hands the body
// to nlohmann::parse at +0xeb378. The old auth endpoint now replies with an
// HTTP 403 HTML page; libDARK converts that to an empty string and aborts with
// parse_error.101. Replace any non-JSON body with a well-formed response so the
// mod can never reach that abort, even if the URL hook is installed a moment
// too late for the request thread.
static constexpr uintptr_t LIBDARK_JSON_PARSE_RVA = 0xe8734;
// 0xeb378 is nlohmann::json::parse(owner, parser-state) called from 0xe87a8.
// Second line of defence when a caller enters the parser through a path that
// does not pass through the 0xe8734 entry point.
static constexpr uintptr_t LIBDARK_PARSE_RVA = 0xeb378;
// libDARK+0xeb81c: `cbz w8, 0xeb8fc` decides whether a parse error throws.
// The mod leaves the throw flag set even for its own empty input, which ends in
// __cxa_throw at 0xeb880 and SIGABRT. Replace it with `b 0xeb8fc` so parse
// errors take the library's own graceful cleanup/return path instead.
static constexpr uintptr_t LIBDARK_THROW_BRANCH_RVA = 0xeb81c;
static constexpr uint32_t LIBDARK_THROW_BRANCH_PATCH = 0x14000038; // b +0xe0
static const char LIBDARK_FALLBACK_JSON[] =
    "{\"status\":false,\"reason\":\"INVALID PARAMETER\","
    "\"data\":{\"real\":\"\",\"token\":\"\",\"modname\":\"\","
    "\"mod_status\":\"\",\"credit\":\"\",\"ESP\":\"off\",\"Item\":\"off\","
    "\"AIM\":\"off\",\"SilentAim\":\"off\",\"BulletTrack\":\"off\","
    "\"Floating\":\"off\",\"Memory\":\"off\",\"Setting\":\"off\","
    "\"expired_date\":\"\",\"EXP\":\"\",\"exdate\":\"\",\"device\":0,"
    "\"rng\":0}}";

static bool looks_like_json(const std::string& s) {
    size_t i = 0;
    while (i < s.size() &&
           (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
        ++i;
    }
    return i < s.size() && (s[i] == '{' || s[i] == '[');
}

static void* hooked_libdark_json_parse(void* owner, int flag, void* input) {
    std::string* body = static_cast<std::string*>(input);
    if (body != nullptr) {
        if (VERBOSE_LOGS) {
            LOGI("[JSON:ENTER] body=%p size=%zu first='%.48s'",
                 body, body->size(), body->c_str());
        }
        if (!looks_like_json(*body)) {
            LOGI("[JSON:FIX] non-JSON auth response (%zu bytes, '%.96s') -> valid JSON",
                 body->size(), body->c_str());
            *body = std::string(LIBDARK_FALLBACK_JSON);
            if (VERBOSE_LOGS) {
                LOGI("[JSON:FIX] now %zu bytes, first='%.48s'",
                     body->size(), body->c_str());
            }
        }
    } else if (VERBOSE_LOGS) {
        LOGW("[JSON:ENTER] null body");
    }
    return original_libdark_json_parse ?
           original_libdark_json_parse(owner, flag, input) : nullptr;
}

static void* hooked_libdark_parse(void* owner, void* state) {
    if (state != nullptr && VERBOSE_LOGS) {
        uintptr_t* words = static_cast<uintptr_t*>(state);
        LOGI("[PARSE:ENTER] state=%p words=%p %p %p %p", state,
             reinterpret_cast<void*>(words[0]), reinterpret_cast<void*>(words[1]),
             reinterpret_cast<void*>(words[2]), reinterpret_cast<void*>(words[3]));
    }
    return original_libdark_parse ? original_libdark_parse(owner, state) : nullptr;
}

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

static void patch_libdark_throw_branch() {
    uintptr_t base = get_library_base("libDARK.so");
    if (!base) return;
    uintptr_t addr = base + LIBDARK_THROW_BRANCH_RVA;
    uint32_t* target = reinterpret_cast<uint32_t*>(addr);
    if (*target == LIBDARK_THROW_BRANCH_PATCH) return; // Already patched.

    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t page = addr & ~static_cast<uintptr_t>(ps - 1);
    size_t span = (addr + sizeof(uint32_t) - page + static_cast<size_t>(ps) - 1) &
                  ~static_cast<size_t>(ps - 1);
    if (mprotect(reinterpret_cast<void*>(page), span,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGW("[PATCH:THROW] mprotect failed at %p", reinterpret_cast<void*>(page));
        return;
    }
    *target = LIBDARK_THROW_BRANCH_PATCH;
    __builtin___clear_cache(reinterpret_cast<char*>(addr),
                            reinterpret_cast<char*>(addr + sizeof(uint32_t)));
    mprotect(reinterpret_cast<void*>(page), span, PROT_READ | PROT_EXEC);
    LOGI("[PATCH:THROW] libDARK+0x%lx -> %08x at %p",
         static_cast<unsigned long>(LIBDARK_THROW_BRANCH_RVA), *target,
         static_cast<const void*>(target));
}

static void install_libdark_rva_hooks() {
    static std::atomic<bool> attempted(false);

    if (minimal_diagnostic_mode()) {
        patch_libdark_throw_branch();
        return;
    }

    bool expected = false;
    if (!attempted.compare_exchange_strong(expected, true)) return;

    if (!get_library_base("libDARK.so")) {
        // Not loaded yet; the dlopen/watcher paths will retry.
        attempted.store(false);
        return;
    }

    std::string path = get_library_path("libDARK.so");
    if (!verify_libdark_build(path)) {
        LOGW("[RVA:LIBDARK] XOR signature not found in %s; skip RVA curl hook",
             path.empty() ? "libDARK.so" : path.c_str());
        attempted.store(false); // Let a later build/reload retry safely.
        return;
    }

    LOGI("[RVA:LIBDARK] XOR blob verified at +0x%lx; hook internal curl_easy_setopt at +0x%lx",
         static_cast<unsigned long>(LIBDARK_BLOB_OFFSET),
         static_cast<unsigned long>(LIBDARK_SETREQ_RVA));

    bool hooked = HookByRVA("libDARK.so", LIBDARK_SETREQ_RVA,
                            reinterpret_cast<void*>(hooked_libdark_curl_easy_setopt),
                            reinterpret_cast<void**>(&original_libdark_curl_easy_setopt),
                            "libDARK curl_easy_setopt");
    if (!hooked) {
        LOGW("[RVA:LIBDARK] RVA hook failed; will retry on next watcher pass");
        attempted.store(false);
    }

    HookByRVA("libDARK.so", LIBDARK_JSON_PARSE_RVA,
              reinterpret_cast<void*>(hooked_libdark_json_parse),
              reinterpret_cast<void**>(&original_libdark_json_parse),
              "libDARK json decode");

    HookByRVA("libDARK.so", LIBDARK_PARSE_RVA,
              reinterpret_cast<void*>(hooked_libdark_parse),
              reinterpret_cast<void**>(&original_libdark_parse),
              "libDARK nlohmann parse");

    patch_libdark_throw_branch();
}

// Diagnostic: dump the first instruction words at the patched RVAs so the log
// proves whether Dobby's branch is still in place when the parse thread runs.
static void log_libdark_patch_bytes(const char* when) {
    uintptr_t base = get_library_base("libDARK.so");
    if (!base) return;
    struct Pair { const char* name; uintptr_t rva; } sites[] = {
        {"curl", LIBDARK_SETREQ_RVA}, {"json", LIBDARK_JSON_PARSE_RVA}
    };
    for (const auto& site : sites) {
        const uint32_t* word = reinterpret_cast<const uint32_t*>(base + site.rva);
        LOGI("[PATCH:%s] libDARK+0x%lx (%p): %08x %08x", when,
             static_cast<unsigned long>(site.rva), static_cast<const void*>(word),
             word[0], word[1]);
    }
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
        if (start >= end || perms[0] != 'r') continue;

        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        segments.push_back({start, end, prot});
    }
    fclose(fp);

    if (segments.empty()) return;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return;

    const uintptr_t page_mask = static_cast<uintptr_t>(page_size) - 1;

    for (const auto& seg : segments) {
        const size_t seg_len = static_cast<size_t>(seg.end - seg.start);

        for (const auto& rule : URL_RULES) {
            if (!rule.enabled || rule.pattern.empty() || rule.replacement.empty()) continue;

            const size_t needle_len = rule.pattern.length();
            const size_t repl_len   = rule.replacement.length();
            if (needle_len > seg_len) continue;

            if (repl_len > needle_len) {
                LOGW("[MEM:PATCH] Replacement '%s' is longer than pattern (%zu > %zu), skipping in-place patch",
                     rule.replacement.c_str(), repl_len, needle_len);
                continue;
            }

            const char* needle  = rule.pattern.c_str();
            const char* repl    = rule.replacement.c_str();
            const char* current = reinterpret_cast<const char*>(seg.start);
            const char* end_ptr = reinterpret_cast<const char*>(seg.end - needle_len);

            while (current <= end_ptr) {
                if (memcmp(current, needle, needle_len) != 0) {
                    ++current;
                    continue;
                }

                const uintptr_t match_addr = reinterpret_cast<uintptr_t>(current);
                const uintptr_t page_start = match_addr & ~page_mask;
                const uintptr_t last_byte  = match_addr + needle_len - 1;
                const uintptr_t page_end   = (last_byte | page_mask) + 1;

                // Never mprotect pages outside this mapping. Touching the next
                // mapping's page (the old 2-page hack) could strip PROT_EXEC from
                // unrelated code and cause SIGSEGV/SEGV_ACCERR.
                if (page_start < seg.start || page_end > seg.end) {
                    LOGW("[MEM:PATCH] Match at %p crosses segment boundary; skipped",
                         reinterpret_cast<void*>(match_addr));
                    current += needle_len;
                    continue;
                }

                const size_t patch_len = static_cast<size_t>(page_end - page_start);
                // Keep executable pages executable while writing; restore exact
                // original flags afterwards (r-x must not become r--).
                const int write_prot = seg.prot | PROT_WRITE;

                if (mprotect(reinterpret_cast<void*>(page_start), patch_len, write_prot) == 0) {
                    memcpy(reinterpret_cast<void*>(match_addr), repl, repl_len);
                    if (repl_len < needle_len) {
                        memset(reinterpret_cast<void*>(match_addr + repl_len), 0,
                               needle_len - repl_len);
                    }

                    __builtin___clear_cache(reinterpret_cast<char*>(page_start),
                                            reinterpret_cast<char*>(page_end));

                    if (mprotect(reinterpret_cast<void*>(page_start), patch_len, seg.prot) != 0) {
                        LOGE("[MEM:PATCH] Failed to restore protection at %p",
                             reinterpret_cast<void*>(page_start));
                    }

                    LOGI("[MEM:PATCH] ✓ Hot-patched '%s' -> '%s' at %p in %s",
                         needle, repl, reinterpret_cast<void*>(match_addr), lib_name);
                } else {
                    LOGE("[MEM:PATCH] mprotect failed at %p (%zu bytes)",
                         reinterpret_cast<void*>(page_start), patch_len);
                }

                current += needle_len;
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
    if (minimal_diagnostic_mode()) {
        if (lib_name.find("libDARK.so") != std::string::npos) {
            patch_libdark_throw_branch();
        }
        return true;
    }

    // Only inspect libraries the app already loaded. Calling dlopen() with
    // RTLD_NOW on an unloaded target would run its constructors in our process
    // (libil2cpp/libUE4/etc.) and is a common crash source.
    void* handle = dlopen(lib_name.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return false;

    bool hooked = install_curl_hooks_from_handle(handle, lib_name.c_str());

    // libDARK.so has a statically linked curl; hook its internal setopt by RVA.
    if (lib_name.find("libDARK.so") != std::string::npos) {
        install_libdark_rva_hooks();
    }

    // Direct in-memory byte patch on the already-loaded library.
    scan_and_patch_memory(lib_name.c_str());

    dlclose(handle); // Drop only the reference we just added.
    return hooked;
}

// ============================================================================
// [12] DLOPEN INTERCEPTOR & WATCHER THREAD
// ============================================================================
static void* fallback_dlopen(const char* filename, int flags) {
    static void* (*real_dlopen)(const char*, int) = nullptr;
    if (!real_dlopen) {
        real_dlopen = reinterpret_cast<void* (*)(const char*, int)>(
            dlsym(RTLD_NEXT, "dlopen"));
    }
    return real_dlopen ? real_dlopen(filename, flags) : nullptr;
}

static void notify_library_loaded(const char* filename, void* handle) {
    if (!filename || !handle) return;
    for (const auto& target : TARGET_LIBS) {
        if (strstr(filename, target.c_str()) != nullptr) {
            if (VERBOSE_LOGS) {
                LOGI("[DLOPEN:DETECTED] Loaded: %s (%p)", filename, handle);
            }
            if (!minimal_diagnostic_mode()) {
                install_curl_hooks_from_handle(handle, filename);
            }
            if (target == "libDARK.so") {
                install_libdark_rva_hooks();
            }
            scan_and_patch_memory(target.c_str());
            break;
        }
    }
}

static void* hooked_dlopen(const char* filename, int flags) {
    // If Dobby/A64 failed to capture the original pointer, still let the app
    // load its library instead of returning nullptr and crashing startup.
    void* handle = original_dlopen ? original_dlopen(filename, flags)
                                   : fallback_dlopen(filename, flags);

    notify_library_loaded(filename, handle);
    return handle;
}

static void* fallback_android_dlopen_ext(const char* filename, int flags, const void* ext) {
    using Fn = void* (*)(const char*, int, const void*);
    static Fn real_fn = nullptr;
    if (!real_fn) {
        real_fn = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "android_dlopen_ext"));
    }
    return real_fn ? real_fn(filename, flags, ext) : nullptr;
}

static void* hooked_android_dlopen_ext(const char* filename, int flags, const void* ext) {
    void* handle = original_android_dlopen_ext
                       ? original_android_dlopen_ext(filename, flags, ext)
                       : fallback_android_dlopen_ext(filename, flags, ext);

    notify_library_loaded(filename, handle);
    return handle;
}

// libDARK spawns its auth/JSON thread from inside dlopen(), so RVA hooks
// installed after dlopen returns are already too late: the thread can call
// curl_easy_setopt and enter the JSON parser before our patches exist.
// Hooking pthread_create lets us patch libDARK BEFORE that thread starts.
static int (*original_pthread_create)(pthread_t*, const pthread_attr_t*,
                                      void* (*)(void*), void*) = nullptr;

static int hooked_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                                 void* (*start_routine)(void*), void* arg) {
    if (start_routine != nullptr && get_library_base("libDARK.so") != 0) {
        uintptr_t base = get_library_base("libDARK.so");
        uintptr_t entry = reinterpret_cast<uintptr_t>(start_routine);
        if (VERBOSE_LOGS) {
            LOGI("[PTHREAD:HOOK] new thread entry %p (libDARK base %p, offset +0x%lx)",
                 start_routine, reinterpret_cast<void*>(base),
                 static_cast<unsigned long>(entry > base ? entry - base : 0));
        }
        install_libdark_rva_hooks();
    }
    return original_pthread_create
               ? original_pthread_create(thread, attr, start_routine, arg)
               : -1;
}

static void install_dlopen_hook() {
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (dlopen_addr) {
        UnifiedHook(dlopen_addr, (void*)hooked_dlopen, (void**)&original_dlopen, "dlopen");
    }

    void* ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (ext_addr) {
        UnifiedHook(ext_addr, (void*)hooked_android_dlopen_ext,
                    (void**)&original_android_dlopen_ext, "android_dlopen_ext");
    }

    void* create_addr = dlsym(RTLD_DEFAULT, "pthread_create");
    if (create_addr) {
        UnifiedHook(create_addr, (void*)hooked_pthread_create,
                    (void**)&original_pthread_create, "pthread_create");
    }
}

// Background watcher checks /proc/self/maps periodically
static void* background_watcher_thread(void*) {
    LOGI("[WATCHER] Background engine monitor started");

    int scan_count = 0;
    while (scan_count < 4000) {
        // libDARK.so can spawn its JSON/auth thread within ~15 ms of being
        // loaded. Poll every 1 ms during startup, then back off to 500 ms.
        usleep(scan_count < 2000 ? 1000 : 500 * 1000);
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
    if (!minimal_diagnostic_mode()) {
        install_dns_hooks();
    }

    // 2. Hook dlopen to intercept newly loaded libraries
    install_dlopen_hook();

    // 3. Hook global curl symbols immediately
    if (HOOK_GLOBAL_CURL && !minimal_diagnostic_mode()) {
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

// ============================================================================
// [15] EARLY-LOAD SLOT
// ============================================================================
// This binary is installed as libPHOENIX.so because that is the first app
// library loaded before libDARK.so. ART calls JNI_OnLoad for it, so all hooks
// are active before libDARK.so starts its JSON/auth thread.
//
// The original libPHOENIX.so is deliberately NOT forwarded: the first app
// library load slot belongs to this hook so it is installed before libDARK.so.
// Note: the parse_error.101 crash is inherent to the Taito mod itself (its
// authapi.xyz endpoint returns 403 HTML that libDARK parses as JSON). The
// JSON-body fallback hook above neutralizes that crash without touching APK
// libraries.

// Compatibility shim: the app calls this JNI method on the library that owns
// the libPHOENIX.so slot. The original Taito libPHOENIX.so exported it; log
// the arguments so the redirect strings remain visible, then return safely.
extern "C" JNIEXPORT void JNICALL
Java_com_pandora_core_AppFactory_initRedirect(JNIEnv* env, jclass clazz,
                                              jstring one, jstring two) {
    (void)clazz;
    if (VERBOSE_LOGS && env != nullptr) {
        const char* s1 = one ? env->GetStringUTFChars(one, nullptr) : nullptr;
        const char* s2 = two ? env->GetStringUTFChars(two, nullptr) : nullptr;
        LOGI("[JNI:initRedirect] '%s' | '%s'", s1 ? s1 : "(null)", s2 ? s2 : "(null)");
        if (s1) env->ReleaseStringUTFChars(one, s1);
        if (s2) env->ReleaseStringUTFChars(two, s2);
    }
}

// IMPORTANT: no __attribute__((constructor)) here. Running the hooking engine
// from the ELF constructor executes during the linker's call_constructors(),
// before all C++ runtime globals are guaranteed usable and on an arbitrary
// loader thread. That path produced the __next_prime overflow abort during
// System.loadLibrary(). ART calls JNI_OnLoad immediately after constructors,
// so this is still early enough to install all hooks for the renamed library.
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("[JNI] JNI_OnLoad called");
    init_engine();
    return JNI_VERSION_1_6;
}

__attribute__((destructor)) static void on_library_unload() {
    LOGI("[CLEANUP] Engine unloading");
}
