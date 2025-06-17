---
title: 浅聊JNI中的Native函数注册
author: fastjien
date: 2025-06-17 10:17:00 +0800
categories: [移动安全, Android逆向]
tags: [Android逆向, JNI]
render_with_liquid: false
mermaid: true
description: 浅聊一下Android逆向中的Native函数注册。这通常是逆向所面临的第一步；
comments: true
pin: false
---
[TOC]



## 静态注册

静态注册是最基础，也是加载效率最快的注册方式。

Native层函数以约定格式命名，并在JVM加载的时候绑定到Java层native函数中。

约定格式是通常是：

```
Java_<包名替换_>_<类名>_<方法名>__[参数签名编码]
```

加入Params签名编码是为了处理函数重载的问题。

如下图例子：

```java
public native void sayHelloFromJNI(String name, byte[] names, String gender, int age);
```

看参数部分：其中引用类型前面要加L，其中不允许出现在函数名中的字符按照约定转义成固定名称。

| 原始 | 转义 |
| ---- | ---- |
| `.`  | `_`  |
| `;`  | `_2` |
| `[`  | `_3` |
| ……   |      |

转义后的C函数名如下：

```c
JNIEXPORT void JNICALL Java_org_example_jni_JniTest_sayHelloFromJNI__Ljava_lang_String_2_3BLjava_lang_String_2I
  (JNIEnv *, jobject, jstring, jbyteArray, jstring, jint);
```

针对静态注册的native，直接去对应so文件中找导出函数，根据函数名辨别即可找到Native中函数的位置。



## 动态注册

静态注册虽简单高效，但却不够灵活。导出函数名必须为固定格式，不可自定义。

另外一种用的很多的方式是手动注册，通过调用`RegisterNatives`函数 动态将C导出函数绑定到对应的native函数上。动态注册不要求C函数的名称，更为灵活。

我们看一下AOSP中`RegisterNatives`这个函数的实现：

```c++
static jint RegisterNatives(JNIEnv* env,
                            jclass java_class,
                            const JNINativeMethod* methods,
                            jint method_count) {
// ……
```

这里暂且只看函数头。这里有一个`const JNINativeMethod* methods` 是一个`JNINativeMethod`结构体数组：

```c++
typedef struct {
    const char* name;
    const char* signature;
    void*       fnPtr;
} JNINativeMethod;
```

结构体包含三个指针，name 函数名称、signature 函数签名、fnPtr 函数指针。

所以只需要hook RegisterNatives这个函数，从`JNINativeMethod`中读出函数及对应的指针位置即可，这里展示imyang的脚本片段（写的很赞）：

```javascript
Interceptor.attach(addrRegisterNatives, {
    onEnter: function (args) {
        console.log("[RegisterNatives] method_count:", args[3]);
        var env = args[0];
        var java_class = args[1];
        var class_name = Java.vm.tryGetEnv().getClassName(java_class);
        //console.log(class_name);

        var methods_ptr = ptr(args[2]);

        var method_count = parseInt(args[3]);
        for (var i = 0; i < method_count; i++) {
            var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
            var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
            var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

            var name = Memory.readCString(name_ptr);
            var sig = Memory.readCString(sig_ptr);
            var find_module = Process.findModuleByAddress(fnPtr_ptr);
            console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, "module_name:", find_module.name, "module_base:", find_module.base, "offset:", ptr(fnPtr_ptr).sub(find_module.base));

        }
    }
});
```



## 更深层次的注册手段

静态注册、动态注册都属于常规注册方式，并没有在对抗层面上做文章。所以常规hook等手段就可以拿到真实的Native函数地址。但听说有种手段可以通过把注册方式下沉（暂时没碰到）不走RegisterNatives，常规的hook手段无效。用来对抗初级的逆向者。

碰到这种情况，我就需要了解Native函数注册更底层的机制，从更底层找到函数注册位置：

```c++
static jint RegisterNatives(JNIEnv* env,
                            jclass java_class,
                            const JNINativeMethod* methods,
                            jint method_count) {
  if (UNLIKELY(method_count < 0)) {
    JavaVmExtFromEnv(env)->JniAbortF("RegisterNatives", "negative method count: %d",
                                     method_count);
    return JNI_ERR;  // Not reached except in unit tests.
  }
  CHECK_NON_NULL_ARGUMENT_FN_NAME("RegisterNatives", java_class, JNI_ERR);
  ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
  ScopedObjectAccess soa(env);
  StackHandleScope<1> hs(soa.Self());
  Handle<mirror::Class> c = hs.NewHandle(soa.Decode<mirror::Class>(java_class));
  if (UNLIKELY(method_count == 0)) {
    LOG(WARNING) << "JNI RegisterNativeMethods: attempt to register 0 native methods for "
                 << c->PrettyDescriptor();
    return JNI_OK;
  }
  ScopedLocalRef<jobject> jclass_loader(env, nullptr);
  if (c->GetClassLoader() != nullptr) {
    jclass_loader.reset(soa.Env()->AddLocalReference<jobject>(c->GetClassLoader()));
  }

  bool is_class_loader_namespace_natively_bridged = false;
  {
    // Making sure to release mutator_lock_ before proceeding.
    // FindNativeLoaderNamespaceByClassLoader eventually acquires lock on g_namespaces_mutex
    // which may cause a deadlock if another thread is waiting for mutator_lock_
    // for IsSameObject call in libnativeloader's CreateClassLoaderNamespace (which happens
    // under g_namespace_mutex lock)
    ScopedThreadSuspension sts(soa.Self(), ThreadState::kNative);

    is_class_loader_namespace_natively_bridged =
        IsClassLoaderNamespaceNativelyBridged(env, jclass_loader.get());
  }

  CHECK_NON_NULL_ARGUMENT_FN_NAME("RegisterNatives", methods, JNI_ERR);
  for (jint i = 0; i < method_count; ++i) {
    const char* name = methods[i].name;
    const char* sig = methods[i].signature;
    const void* fnPtr = methods[i].fnPtr;
    if (UNLIKELY(name == nullptr)) {
      ReportInvalidJNINativeMethod(soa, c.Get(), "method name", i);
      return JNI_ERR;
    } else if (UNLIKELY(sig == nullptr)) {
      ReportInvalidJNINativeMethod(soa, c.Get(), "method signature", i);
      return JNI_ERR;
    } else if (UNLIKELY(fnPtr == nullptr)) {
      ReportInvalidJNINativeMethod(soa, c.Get(), "native function", i);
      return JNI_ERR;
    }
    bool is_fast = false;
    // Notes about fast JNI calls:
    //
    // On a normal JNI call, the calling thread usually transitions
    // from the kRunnable state to the kNative state. But if the
    // called native function needs to access any Java object, it
    // will have to transition back to the kRunnable state.
    //
    // There is a cost to this double transition. For a JNI call
    // that should be quick, this cost may dominate the call cost.
    //
    // On a fast JNI call, the calling thread avoids this double
    // transition by not transitioning from kRunnable to kNative and
    // stays in the kRunnable state.
    //
    // There are risks to using a fast JNI call because it can delay
    // a response to a thread suspension request which is typically
    // used for a GC root scanning, etc. If a fast JNI call takes a
    // long time, it could cause longer thread suspension latency
    // and GC pauses.
    //
    // Thus, fast JNI should be used with care. It should be used
    // for a JNI call that takes a short amount of time (eg. no
    // long-running loop) and does not block (eg. no locks, I/O,
    // etc.)
    //
    // A '!' prefix in the signature in the JNINativeMethod
    // indicates that it's a fast JNI call and the runtime omits the
    // thread state transition from kRunnable to kNative at the
    // entry.
    if (*sig == '!') {
      is_fast = true;
      ++sig;
    }

    // Note: the right order is to try to find the method locally
    // first, either as a direct or a virtual method. Then move to
    // the parent.
    ArtMethod* m = nullptr;
    bool warn_on_going_to_parent = down_cast<JNIEnvExt*>(env)->GetVm()->IsCheckJniEnabled();
    for (ObjPtr<mirror::Class> current_class = c.Get();
         current_class != nullptr;
         current_class = current_class->GetSuperClass()) {
      // Search first only comparing methods which are native.
      m = FindMethod<true>(current_class, name, sig);
      if (m != nullptr) {
        break;
      }

      // Search again comparing to all methods, to find non-native methods that match.
      m = FindMethod<false>(current_class, name, sig);
      if (m != nullptr) {
        break;
      }

      if (warn_on_going_to_parent) {
        LOG(WARNING) << "CheckJNI: method to register \"" << name << "\" not in the given class. "
                     << "This is slow, consider changing your RegisterNatives calls.";
        warn_on_going_to_parent = false;
      }
    }

    if (m == nullptr) {
      c->DumpClass(LOG_STREAM(ERROR), mirror::Class::kDumpClassFullDetail);
      LOG(ERROR)
          << "Failed to register native method "
          << c->PrettyDescriptor() << "." << name << sig << " in "
          << c->GetDexCache()->GetLocation()->ToModifiedUtf8();
      ThrowNoSuchMethodError(soa, c.Get(), name, sig, "static or non-static");
      return JNI_ERR;
    } else if (!m->IsNative()) {
      LOG(ERROR)
          << "Failed to register non-native method "
          << c->PrettyDescriptor() << "." << name << sig
          << " as native";
      ThrowNoSuchMethodError(soa, c.Get(), name, sig, "native");
      return JNI_ERR;
    }

    VLOG(jni) << "[Registering JNI native method " << m->PrettyMethod() << "]";

    if (UNLIKELY(is_fast)) {
      // There are a few reasons to switch:
      // 1) We don't support !bang JNI anymore, it will turn to a hard error later.
      // 2) @FastNative is actually faster. At least 1.5x faster than !bang JNI.
      //    and switching is super easy, remove ! in C code, add annotation in .java code.
      // 3) Good chance of hitting DCHECK failures in ScopedFastNativeObjectAccess
      //    since that checks for presence of @FastNative and not for ! in the descriptor.
      LOG(WARNING) << "!bang JNI is deprecated. Switch to @FastNative for " << m->PrettyMethod();
      is_fast = false;
      // TODO: make this a hard register error in the future.
    }

    // It is possible to link a class with native methods from a library loaded by
    // a different classloader. In this case IsClassLoaderNamespaceNativelyBridged
    // fails detect if native bridge is enabled and may return false.
    // For this reason we always check method with native bridge (see b/393035780
    // for details).
    if (is_class_loader_namespace_natively_bridged ||
        android::NativeBridgeIsNativeBridgeFunctionPointer(fnPtr)) {
      fnPtr = GenerateNativeBridgeTrampoline(fnPtr, m);
    }
    const void* final_function_ptr = class_linker->RegisterNative(soa.Self(), m, fnPtr);
    UNUSED(final_function_ptr);
  }
  return JNI_OK;
}
```



**TO BE CONTINUE……**

