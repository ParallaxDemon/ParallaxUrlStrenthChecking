LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dobby
LOCAL_SRC_FILES := Dobby/$(TARGET_ARCH_ABI)/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := urlhook
LOCAL_SRC_FILES := Main.cpp And64InlineHook/And64InlineHook.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/Dobby $(LOCAL_PATH)/And64InlineHook $(LOCAL_PATH)
LOCAL_CPP_EXTENSION := .cpp .cc

LOCAL_CFLAGS := -Wno-error=format-security -fvisibility=hidden -ffunction-sections -fdata-sections -w
LOCAL_CFLAGS += -fno-rtti -fpermissive

LOCAL_CPPFLAGS := -std=c++17
LOCAL_CPPFLAGS += -fexceptions
LOCAL_CPPFLAGS += -Wno-error=format-security -fvisibility=hidden -ffunction-sections -fdata-sections -w
LOCAL_CPPFLAGS += -fms-extensions -fno-rtti -fpermissive

LOCAL_LDLIBS := -llog -ldl
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all

LOCAL_ARM_MODE := arm
LOCAL_STATIC_LIBRARIES := dobby

include $(BUILD_SHARED_LIBRARY)