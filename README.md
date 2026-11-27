# ParallaxUrlStrengthChecking 🚀 (Maximum Edition)

[![Build liburlhook.so](https://github.com/ParallaxDemon/ParallaxUrlStrenthChecking/actions/workflows/build-libso.yml/badge.svg)](https://github.com/ParallaxDemon/ParallaxUrlStrenthChecking/actions/workflows/build-libso.yml)

> **Ultra Runtime URL Redirection & Multi-Layer Hooking Engine for Android Native Libraries**  
> Developed with ❤️ by **[ParallaxDemon](https://github.com/ParallaxDemon)**  
> Integrated with **[Dobby Hook](https://github.com/jmpews/Dobby)** & **[And64InlineHook](https://github.com/Rprop/And64InlineHook)** (by Rprop)

---

## 🌟 Overview

**ParallaxUrlStrengthChecking** is an all-in-one native Android hooking & memory patching library (`liburlhook.so`) engineered in modern **C++17**.

It provides a **5-Layer Redirection Pipeline** designed to intercept, rewrite, and redirect URLs and domain names **under any circumstance** — whether the target application uses `libcurl`, modern `curl_url_set`, raw TCP sockets, or hardcoded string constants in stripped binaries.

---

## 🛡️ 5-Layer Maximum Interception Architecture

```
[Target App / Game]
        │
        ├──► [Layer 1: DNS Interception] ──────► Redirects hostname at OS libc level (getaddrinfo/gethostbyname)
        │                                        (Redirects ANY native socket/HTTP client to new domain)
        │
        ├──► [Layer 2: cURL API Interception] ──► Hooks curl_easy_setopt (CURLOPT_URL) & curl_url_set
        │                                        + Full SSL/TLS Pinning Bypass (Peer/Host/Status = 0)
        │
        ├──► [Layer 3: In-Memory Hot-Patcher] ──► Scans mapped memory pages (/proc/self/maps)
        │                                        mprotect write-patching for hardcoded strings in RAM
        │
        ├──► [Layer 4: Dual Hooking Engines] ───► Hybrid Dobby + And64InlineHook (Rprop)
        │                                        Auto-fallback + Direct RVA offset hooking support
        │
        └──► [Layer 5: C++-only Rules] ──────────► URLs hard-coded in Main.cpp
                                                 No config file / external dependency at all
```

---

## ✨ Features Breakdown

### 1. Dual Hooking Engines (Dobby + And64InlineHook Hybrid)
- **Primary:** High-speed Dobby inline hooker.
- **Fallback:** [And64InlineHook](https://github.com/Rprop/And64InlineHook) (by Rprop). If Dobby encounters instruction relocation issues or PAC on ARM64, the engine automatically falls back to `A64HookFunction`.
- **RVA Offset Hooking:** Easily hook stripped/unexported functions directly by memory offset:
  ```cpp
  HookByRVA("libil2cpp.so", 0x1A2B3C, (void*)my_hook, (void**)&orig_func, "internal_func");
  ```

### 2. DNS-Level Interception (`getaddrinfo` / `gethostbyname`)
- Intercepts DNS queries in `libc.so`.
- When the app resolves `taitogaming.authapi.xyz`, it is sent to `darkdevel.parallaxserver.online` before the socket is created.
- **Works even if cURL is completely stripped or custom sockets are used!**

### 3. In-Memory String Scanner & Hot-Patcher (`mprotect`)
- Scans all mapped memory pages (`.rodata`, `.data`) of target libraries (`libil2cpp.so`, etc.).
- Finds byte occurrences of old URLs/domains and directly overwrites them in process memory.
- **Page-safe:** only the exact pages covering a match are `mprotect`-ed, never a fixed 2-page window that could hit a neighbouring mapping.
- **W^X-safe:** executable pages keep `PROT_EXEC` while writing, and the original flags (`r-x`, `rw-`, ...) are restored afterwards. This fixes `SIGSEGV / SEGV_ACCERR: trying to execute non-executable memory`.
- Cache flush (`__builtin___clear_cache`) runs before restoring protections.

### 4. Crash-Proof Memory Lifecycle Tracking
- Prevents use-after-free crashes (`SIGSEGV`) by maintaining a thread-safe map of allocated URL strings tied to their `CURL*` handle.
- Memory is safely released only when `curl_easy_cleanup` is called.

### 5. Full SSL / TLS Pinning Bypass
- Automatically overrides:
  - `CURLOPT_SSL_VERIFYPEER` (64) = 0
  - `CURLOPT_SSL_VERIFYHOST` (81) = 0
  - `CURLOPT_SSL_VERIFYSTATUS` (232) = 0
  - Clears `CURLOPT_CAINFO` and `CURLOPT_CAPATH`.
- Eliminates `curl error 60` (`CURLE_PEER_FAILED_VERIFICATION`) when redirecting to custom or self-signed servers.

### 6. C++-Only Hard-coded Rules
- All redirect rules, target libraries and settings live in `app/src/main/jni/Main.cpp` only.
- No `/sdcard/url_config.json`, no sample config, no file/env/network dependency — nothing is read at runtime.
- To change a redirect, edit `URL_RULES` in `Main.cpp` and rebuild `liburlhook.so`.

### 7. Crash Hardening (final pass)
- **NOLOAD-only scanning:** `check_and_hook_library()` never calls `dlopen()` with `RTLD_NOW` on an unloaded target. Constructors of `libil2cpp.so`, `libUE4.so`, `libmain.so`, etc. are no longer accidentally run inside the host process.
- **dlopen fallback:** if a hook engine fails to capture the original `dlopen`, `dlsym(RTLD_NEXT, "dlopen")` is used so the app still loads its libraries instead of getting `nullptr`.
- **Retry-safe RVA hook:** a failed/mismatched `libDARK.so` signature check no longer permanently disables the RVA hook; the watcher retries safely.
- **Self-hook guard:** the hook dispatcher refuses to hook its own trampoline address.
- **Empty-rule guard:** empty patterns can never trigger a zero-length replace loop.

---

## 🛠️ Configuration Guide

### Hard-coded Rules (`app/src/main/jni/Main.cpp`) — no config file

```cpp
static std::vector<UrlRule> URL_RULES = {
    // 0. Requested redirect: taitogaming auth endpoint -> darkdevel panel
    {
        "https://taitogaming.authapi.xyz/server",
        "https://darkdevel.parallaxserver.online/connect",
        MatchType::EXACT,
        true,
        "Taito -> Darkdevel Auth Endpoint"
    },

    // 0b. Domain fallback for any other path on the old host
    {
        "taitogaming.authapi.xyz",
        "darkdevel.parallaxserver.online",
        MatchType::DOMAIN,
        true,
        "Taito -> Darkdevel Domain Swap"
    }
};
```

### Current built-in redirect

| From | To |
|---|---|
| `https://taitogaming.authapi.xyz/server` | `https://darkdevel.parallaxserver.online/connect` |
| `taitogaming.authapi.xyz` (any host-level lookup) | `darkdevel.parallaxserver.online` |
| `https://teamruthless.authapi.xyz/connect` | `https://darkdevel.parallaxserver.online/connect` |
| `teamruthless.authapi.xyz` (any host-level lookup) | `darkdevel.parallaxserver.online` |
| `authapi.xyz` (any remaining substring) | `darkdevel.parallaxserver.online` |

Sirf `darkdevel.parallaxserver.online` target hai — koi placeholder/host nahi. Endpoint ko app ke expected JSON schema ka response dena zaroori hai, warna `libDARK.so` me `nlohmann::parse_error` se SIGABRT aayega.

`libDARK.so` is in `TARGET_LIBS`. Because that library stores the URL as an XOR blob finished from code immediates and links curl statically, the engine also verifies the blob at `libDARK+0x305e40` (XOR key `0x2E`) and, on the matching build, hooks the internal `curl_easy_setopt` at `libDARK+0x126618`. A different build fails the signature check and is left untouched instead of being patched at a wrong offset.

---

## 🔨 Build Instructions

### GitHub Actions (main branch)

`.github/workflows/build-libso.yml` har `push` / `pull_request` par `main` branch ke liye chaaron ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) build karta hai. Har build me **standalone linkage check** hota hai (`libc++_shared.so` NEEDED nahi hona chahiye) aur `liburlhook-all-<commit-sha>.zip` bhi banata hai. Output `liburlhook-all-<commit-sha>` artifact Actions tab se download karo. `workflow_dispatch` se manually bhi chala sakte ho.

### Method A: Termux / Linux Build (ARM64)

```bash
cd /data/user/0/com.termux/files/home/projects/ParallaxUrlStrenthChecking

clang++ -std=c++17 -shared -fPIC -O2 \
  -I app/src/main/jni/Dobby \
  -I app/src/main/jni/And64InlineHook \
  -I app/src/main/jni \
  app/src/main/jni/Main.cpp \
  app/src/main/jni/And64InlineHook/And64InlineHook.cpp \
  app/src/main/jni/Dobby/arm64-v8a/libdobby.a \
  -llog -ldl \
  -o app/src/main/jniLibs/arm64-v8a/liburlhook.so

strip --strip-unneeded app/src/main/jniLibs/arm64-v8a/liburlhook.so
```

### Method B: Android NDK Build (`ndk-build`)

```bash
cd app/src/main/jni
ndk-build
```

---

## 📱 How to Inject & Run

1. **Via `System.loadLibrary`**:
   ```java
   System.loadLibrary("urlhook");
   ```

2. **Via APK Injection (MT Manager / NP Manager)**:
   - Copy `liburlhook.so` into `lib/arm64-v8a/` inside the APK.
   - **Self-contained:** `libc++` aur Dobby statically linked hain. Sirf system libs (`libc.so`, `libdl.so`, `liblog.so`, `libm.so`) lagti hain — `libc++_shared.so` copy karne ki zarurat nahi.
   - Inject `const-string v0, "urlhook"` -> `invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V` into `Application.onCreate()` or `MainActivity.onCreate()`.

3. **Monitor Real-Time Logs via Logcat**:
   ```bash
   adb logcat -s URL_HOOK
   ```

---

## ⚖️ Credits & License

- **[Dobby](https://github.com/jmpews/Dobby)** by jmpews.
- **[And64InlineHook](https://github.com/Rprop/And64InlineHook)** by Rprop.
- Created and maintained by **[ParallaxDemon](https://github.com/ParallaxDemon)**.
