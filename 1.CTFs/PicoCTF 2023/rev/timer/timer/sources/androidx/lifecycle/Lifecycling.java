package androidx.lifecycle;

import androidx.lifecycle.Lifecycle;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class Lifecycling {
    private static final int GENERATED_CALLBACK = 2;
    private static final int REFLECTIVE_CALLBACK = 1;
    private static Map<Class<?>, Integer> sCallbackCache = new HashMap();
    private static Map<Class<?>, List<Constructor<? extends GeneratedAdapter>>> sClassToAdapters = new HashMap();

    @Deprecated
    static GenericLifecycleObserver getCallback(Object object) {
        final LifecycleEventObserver observer = lifecycleEventObserver(object);
        return new GenericLifecycleObserver() { // from class: androidx.lifecycle.Lifecycling.1
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                LifecycleEventObserver.this.onStateChanged(source, event);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static LifecycleEventObserver lifecycleEventObserver(Object object) {
        boolean isLifecycleEventObserver = object instanceof LifecycleEventObserver;
        boolean isFullLifecycleObserver = object instanceof FullLifecycleObserver;
        if (isLifecycleEventObserver && isFullLifecycleObserver) {
            return new FullLifecycleObserverAdapter((FullLifecycleObserver) object, (LifecycleEventObserver) object);
        }
        if (isFullLifecycleObserver) {
            return new FullLifecycleObserverAdapter((FullLifecycleObserver) object, null);
        }
        if (isLifecycleEventObserver) {
            return (LifecycleEventObserver) object;
        }
        Class<?> klass = object.getClass();
        int type = getObserverConstructorType(klass);
        if (type == 2) {
            List<Constructor<? extends GeneratedAdapter>> constructors = sClassToAdapters.get(klass);
            if (constructors.size() == 1) {
                GeneratedAdapter generatedAdapter = createGeneratedAdapter(constructors.get(0), object);
                return new SingleGeneratedAdapterObserver(generatedAdapter);
            }
            GeneratedAdapter[] adapters = new GeneratedAdapter[constructors.size()];
            for (int i = 0; i < constructors.size(); i++) {
                adapters[i] = createGeneratedAdapter(constructors.get(i), object);
            }
            return new CompositeGeneratedAdaptersObserver(adapters);
        }
        return new ReflectiveGenericLifecycleObserver(object);
    }

    private static GeneratedAdapter createGeneratedAdapter(Constructor<? extends GeneratedAdapter> constructor, Object object) {
        try {
            return constructor.newInstance(object);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e2) {
            throw new RuntimeException(e2);
        } catch (InvocationTargetException e3) {
            throw new RuntimeException(e3);
        }
    }

    private static Constructor<? extends GeneratedAdapter> generatedConstructor(Class<?> klass) {
        String str;
        try {
            Package aPackage = klass.getPackage();
            String name = klass.getCanonicalName();
            String fullPackage = aPackage != null ? aPackage.getName() : "";
            String adapterName = getAdapterName(fullPackage.isEmpty() ? name : name.substring(fullPackage.length() + 1));
            if (fullPackage.isEmpty()) {
                str = adapterName;
            } else {
                str = fullPackage + "." + adapterName;
            }
            Constructor declaredConstructor = Class.forName(str).getDeclaredConstructor(klass);
            if (!declaredConstructor.isAccessible()) {
                declaredConstructor.setAccessible(true);
            }
            return declaredConstructor;
        } catch (ClassNotFoundException e) {
            return null;
        } catch (NoSuchMethodException e2) {
            throw new RuntimeException(e2);
        }
    }

    private static int getObserverConstructorType(Class<?> klass) {
        Integer callbackCache = sCallbackCache.get(klass);
        if (callbackCache != null) {
            return callbackCache.intValue();
        }
        int type = resolveObserverCallbackType(klass);
        sCallbackCache.put(klass, Integer.valueOf(type));
        return type;
    }

    private static int resolveObserverCallbackType(Class<?> klass) {
        Class<?>[] interfaces;
        if (klass.getCanonicalName() == null) {
            return 1;
        }
        Constructor<? extends GeneratedAdapter> constructor = generatedConstructor(klass);
        if (constructor != null) {
            sClassToAdapters.put(klass, Collections.singletonList(constructor));
            return 2;
        }
        boolean hasLifecycleMethods = ClassesInfoCache.sInstance.hasLifecycleMethods(klass);
        if (hasLifecycleMethods) {
            return 1;
        }
        Class<?> superclass = klass.getSuperclass();
        List<Constructor<? extends GeneratedAdapter>> adapterConstructors = null;
        if (isLifecycleParent(superclass)) {
            if (getObserverConstructorType(superclass) == 1) {
                return 1;
            }
            adapterConstructors = new ArrayList<>(sClassToAdapters.get(superclass));
        }
        for (Class<?> intrface : klass.getInterfaces()) {
            if (isLifecycleParent(intrface)) {
                if (getObserverConstructorType(intrface) == 1) {
                    return 1;
                }
                if (adapterConstructors == null) {
                    adapterConstructors = new ArrayList<>();
                }
                adapterConstructors.addAll(sClassToAdapters.get(intrface));
            }
        }
        if (adapterConstructors != null) {
            sClassToAdapters.put(klass, adapterConstructors);
            return 2;
        }
        return 1;
    }

    private static boolean isLifecycleParent(Class<?> klass) {
        return klass != null && LifecycleObserver.class.isAssignableFrom(klass);
    }

    public static String getAdapterName(String className) {
        return className.replace(".", "_") + "_LifecycleAdapter";
    }

    private Lifecycling() {
    }
}
