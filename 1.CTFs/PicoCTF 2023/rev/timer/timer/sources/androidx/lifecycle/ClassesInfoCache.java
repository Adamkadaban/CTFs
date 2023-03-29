package androidx.lifecycle;

import androidx.lifecycle.Lifecycle;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
@Deprecated
/* loaded from: classes.dex */
final class ClassesInfoCache {
    private static final int CALL_TYPE_NO_ARG = 0;
    private static final int CALL_TYPE_PROVIDER = 1;
    private static final int CALL_TYPE_PROVIDER_WITH_EVENT = 2;
    static ClassesInfoCache sInstance = new ClassesInfoCache();
    private final Map<Class<?>, CallbackInfo> mCallbackMap = new HashMap();
    private final Map<Class<?>, Boolean> mHasLifecycleMethods = new HashMap();

    ClassesInfoCache() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasLifecycleMethods(Class<?> klass) {
        Boolean hasLifecycleMethods = this.mHasLifecycleMethods.get(klass);
        if (hasLifecycleMethods != null) {
            return hasLifecycleMethods.booleanValue();
        }
        Method[] methods = getDeclaredMethods(klass);
        for (Method method : methods) {
            OnLifecycleEvent annotation = (OnLifecycleEvent) method.getAnnotation(OnLifecycleEvent.class);
            if (annotation != null) {
                createInfo(klass, methods);
                return true;
            }
        }
        this.mHasLifecycleMethods.put(klass, false);
        return false;
    }

    private Method[] getDeclaredMethods(Class<?> klass) {
        try {
            return klass.getDeclaredMethods();
        } catch (NoClassDefFoundError e) {
            throw new IllegalArgumentException("The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot access even other methods so you should make sure that your observer classes only access framework classes that are available in your min API level OR use lifecycle:compiler annotation processor.", e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CallbackInfo getInfo(Class<?> klass) {
        CallbackInfo existing = this.mCallbackMap.get(klass);
        if (existing != null) {
            return existing;
        }
        return createInfo(klass, null);
    }

    private void verifyAndPutHandler(Map<MethodReference, Lifecycle.Event> handlers, MethodReference newHandler, Lifecycle.Event newEvent, Class<?> klass) {
        Lifecycle.Event event = handlers.get(newHandler);
        if (event != null && newEvent != event) {
            Method method = newHandler.mMethod;
            throw new IllegalArgumentException("Method " + method.getName() + " in " + klass.getName() + " already declared with different @OnLifecycleEvent value: previous value " + event + ", new value " + newEvent);
        } else if (event == null) {
            handlers.put(newHandler, newEvent);
        }
    }

    private CallbackInfo createInfo(Class<?> klass, Method[] declaredMethods) {
        CallbackInfo superInfo;
        Class<?> superclass = klass.getSuperclass();
        Map<MethodReference, Lifecycle.Event> handlerToEvent = new HashMap<>();
        if (superclass != null && (superInfo = getInfo(superclass)) != null) {
            handlerToEvent.putAll(superInfo.mHandlerToEvent);
        }
        Class<?>[] interfaces = klass.getInterfaces();
        char c = 0;
        for (Class<?> intrfc : interfaces) {
            for (Map.Entry<MethodReference, Lifecycle.Event> entry : getInfo(intrfc).mHandlerToEvent.entrySet()) {
                verifyAndPutHandler(handlerToEvent, entry.getKey(), entry.getValue(), klass);
            }
        }
        Method[] methods = declaredMethods != null ? declaredMethods : getDeclaredMethods(klass);
        boolean hasLifecycleMethods = false;
        int length = methods.length;
        int i = 0;
        while (i < length) {
            Method method = methods[i];
            OnLifecycleEvent annotation = (OnLifecycleEvent) method.getAnnotation(OnLifecycleEvent.class);
            if (annotation != null) {
                hasLifecycleMethods = true;
                Class<?>[] params = method.getParameterTypes();
                int callType = 0;
                if (params.length > 0) {
                    callType = 1;
                    if (!params[c].isAssignableFrom(LifecycleOwner.class)) {
                        throw new IllegalArgumentException("invalid parameter type. Must be one and instanceof LifecycleOwner");
                    }
                }
                Lifecycle.Event event = annotation.value();
                if (params.length > 1) {
                    callType = 2;
                    if (!params[1].isAssignableFrom(Lifecycle.Event.class)) {
                        throw new IllegalArgumentException("invalid parameter type. second arg must be an event");
                    }
                    if (event != Lifecycle.Event.ON_ANY) {
                        throw new IllegalArgumentException("Second arg is supported only for ON_ANY value");
                    }
                }
                if (params.length > 2) {
                    throw new IllegalArgumentException("cannot have more than 2 params");
                }
                MethodReference methodReference = new MethodReference(callType, method);
                verifyAndPutHandler(handlerToEvent, methodReference, event, klass);
            }
            i++;
            c = 0;
        }
        CallbackInfo info = new CallbackInfo(handlerToEvent);
        this.mCallbackMap.put(klass, info);
        this.mHasLifecycleMethods.put(klass, Boolean.valueOf(hasLifecycleMethods));
        return info;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Deprecated
    /* loaded from: classes.dex */
    public static class CallbackInfo {
        final Map<Lifecycle.Event, List<MethodReference>> mEventToHandlers = new HashMap();
        final Map<MethodReference, Lifecycle.Event> mHandlerToEvent;

        CallbackInfo(Map<MethodReference, Lifecycle.Event> handlerToEvent) {
            this.mHandlerToEvent = handlerToEvent;
            for (Map.Entry<MethodReference, Lifecycle.Event> entry : handlerToEvent.entrySet()) {
                Lifecycle.Event event = entry.getValue();
                List<MethodReference> methodReferences = this.mEventToHandlers.get(event);
                if (methodReferences == null) {
                    methodReferences = new ArrayList();
                    this.mEventToHandlers.put(event, methodReferences);
                }
                methodReferences.add(entry.getKey());
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void invokeCallbacks(LifecycleOwner source, Lifecycle.Event event, Object target) {
            invokeMethodsForEvent(this.mEventToHandlers.get(event), source, event, target);
            invokeMethodsForEvent(this.mEventToHandlers.get(Lifecycle.Event.ON_ANY), source, event, target);
        }

        private static void invokeMethodsForEvent(List<MethodReference> handlers, LifecycleOwner source, Lifecycle.Event event, Object mWrapped) {
            if (handlers != null) {
                for (int i = handlers.size() - 1; i >= 0; i--) {
                    handlers.get(i).invokeCallback(source, event, mWrapped);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Deprecated
    /* loaded from: classes.dex */
    public static final class MethodReference {
        final int mCallType;
        final Method mMethod;

        MethodReference(int callType, Method method) {
            this.mCallType = callType;
            this.mMethod = method;
            method.setAccessible(true);
        }

        void invokeCallback(LifecycleOwner source, Lifecycle.Event event, Object target) {
            try {
                switch (this.mCallType) {
                    case 0:
                        this.mMethod.invoke(target, new Object[0]);
                        return;
                    case 1:
                        this.mMethod.invoke(target, source);
                        return;
                    case 2:
                        this.mMethod.invoke(target, source, event);
                        return;
                    default:
                        return;
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (InvocationTargetException e2) {
                throw new RuntimeException("Failed to call observer method", e2.getCause());
            }
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o instanceof MethodReference) {
                MethodReference that = (MethodReference) o;
                return this.mCallType == that.mCallType && this.mMethod.getName().equals(that.mMethod.getName());
            }
            return false;
        }

        public int hashCode() {
            return (this.mCallType * 31) + this.mMethod.getName().hashCode();
        }
    }
}
