# ParallaxUrlStrengthChecking 🚀

> **Ultra Runtime URL Redirection & Dynamic Curl Hook Engine for Android Native Libraries**  
> Developed with ❤️ by **[ParallaxDemon](https://github.com/ParallaxDemon)**

---

## 🌟 Overview

**ParallaxUrlStrengthChecking** is a high-performance native Android shared library (`liburlhook.so`) powered by the **Dobby Hook** framework and modern **C++17**.

It intercepts native `libcurl` network calls across target Android libraries (e.g., `libil2cpp.so`, `libanogs.so`, `libUE4.so`) and dynamically rewrites URLs, domains, and endpoints in real-time — **without modifying the game or target APK's original binary**.

---

## ✨ Ultra-Level Features

- 🎯 **Multi-Target Library Support**:
  - Automatically identifies and hooks `libil2cpp.so` (Unity), `libanogs.so` (Anti-cheat), `libUE4.so` (Unreal Engine), `libcurl.so`, or any custom native library.
  - Also resolves and hooks global curl symbols (`RTLD_DEFAULT`).

- ⚡ **Dynamic `dlopen` Interception & Background Watcher**:
  - Hooks `dlopen` to instantly catch target libraries the millisecond they are loaded into memory.
  - Features an asynchronous `/proc/self/maps` scanner thread as a fail-safe against custom linkers or packers. Zero race conditions!

- 🔄 **Ultra Multi-Rule URL Transformation Engine**:
  - **`MatchType::EXACT`**: Replaces the entire URL string exactly.
  - **`MatchType::DOMAIN`**: Replaces only the domain/host while preserving paths, parameters, and query strings.
  - **`MatchType::PREFIX`**: Replaces URLs starting with a designated prefix.
  - **`MatchType::CONTAINS`**: Replaces all occurrences of a designated substring.
  - **`MatchType::REGEX`**: Advanced pattern matching and regex substitution.

- 🛡️ **Crash-Proof Memory Lifecycle Management**:
  - Naive hookers that `free()` modified strings inside `curl_easy_setopt` cause immediate `SIGSEGV` / heap corruption crashes during `curl_easy_perform`.
  - This engine features a thread-safe handle allocation tracker (`std::unordered_map<void*, std::vector<char*>>`) that guarantees strings remain valid throughout the request lifecycle and are safely freed during `curl_easy_cleanup()`.

- 🔓 **Full SSL / TLS Verification Override**:
  - Automatically forces `CURLOPT_SSL_VERIFYPEER = 0`, `CURLOPT_SSL_VERIFYHOST = 0`, and `CURLOPT_SSL_VERIFYSTATUS = 0`.
  - Fixes `curl` Error 60 (`CURLE_PEER_FAILED_VERIFICATION`) and allows seamless routing to custom self-signed endpoints or proxies.
  - Optional automatic `http://` to `https://` protocol upgrades.

- 📊 **Detailed Logcat Diagnostics**:
  - Real-time logging under the tag `URL_HOOK` showing execution time, handle addresses, original URLs, and rewritten destinations.

---

## 🛠️ Configuration Guide

All configuration is located in [`app/src/main/jni/Main.cpp`](app/src/main/jni/Main.cpp).

### 1. Adding Redirection Rules

```cpp
static const std::vector<UrlRule> URL_RULES = {
    // 1. Full URL exact match
    {
        "https://api.oldserver.com/v1/auth",
        "https://api.newserver.com/v1/auth",
        MatchType::EXACT,
        true,
        "Auth Endpoint"
    },

    // 2. Domain replacement (keeps /path?query intact)
    {
        "oldserver.com",
        "newserver.com",
        MatchType::DOMAIN,
        true,
        "Domain Swap"
    },

    // 3. Substring replacement
    {
        "oldkeyword",
        "newkeyword",
        MatchType::CONTAINS,
        true,
        "Keyword Swap"
    }
};
```

### 2. Specifying Target Libraries

```cpp
static const std::vector<std::string> TARGET_LIBS = {
    "libil2cpp.so",    // Unity
    "libanogs.so",     // Tencent / Anti-Cheat
    "libUE4.so",       // Unreal Engine
    "libcurl.so"       // Standard curl
};
```

---

## 🔨 Build Instructions

### Method A: Direct Termux / Linux Build (ARM64)

```bash
clang++ -std=c++17 -shared -fPIC -O2 \
  -I app/src/main/jni/Dobby \
  app/src/main/jni/Main.cpp \
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

Compiled `.so` binaries will be output to `app/src/main/libs/` or `app/src/main/jniLibs/` for all architectures (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`).

---

## 📱 How to Inject & Run

1. **Via `System.loadLibrary`**:
   Load `liburlhook.so` before the target library in your app or mod menu:
   ```java
   System.loadLibrary("urlhook");
   ```

2. **Via APK Injection (NP Manager / MT Manager)**:
   - Add `liburlhook.so` to the APK's `lib/<arch>/` directory.
   - Inject `System.loadLibrary("urlhook")` inside the `Application.onCreate()` or `MainActivity.onCreate()` Smali bytecode.

3. **Monitor Logs via Logcat**:
   ```bash
   adb logcat -s URL_HOOK
   ```

---

## ⚖️ License & Disclaimer

This project is created by **ParallaxDemon** for educational, security auditing, and API migration testing purposes.
