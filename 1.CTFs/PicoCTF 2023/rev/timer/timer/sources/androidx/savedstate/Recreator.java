package androidx.savedstate;

import android.os.Bundle;
import androidx.lifecycle.GenericLifecycleObserver;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleOwner;
import androidx.savedstate.SavedStateRegistry;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class Recreator implements GenericLifecycleObserver {
    static final String CLASSES_KEY = "classes_to_restore";
    static final String COMPONENT_KEY = "androidx.savedstate.Restarter";
    private final SavedStateRegistryOwner mOwner;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Recreator(SavedStateRegistryOwner owner) {
        this.mOwner = owner;
    }

    @Override // androidx.lifecycle.LifecycleEventObserver
    public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
        if (event != Lifecycle.Event.ON_CREATE) {
            throw new AssertionError("Next event must be ON_CREATE");
        }
        source.getLifecycle().removeObserver(this);
        Bundle bundle = this.mOwner.getSavedStateRegistry().consumeRestoredStateForKey(COMPONENT_KEY);
        if (bundle == null) {
            return;
        }
        ArrayList<String> classes = bundle.getStringArrayList(CLASSES_KEY);
        if (classes == null) {
            throw new IllegalStateException("Bundle with restored state for the component \"androidx.savedstate.Restarter\" must contain list of strings by the key \"classes_to_restore\"");
        }
        Iterator<String> it = classes.iterator();
        while (it.hasNext()) {
            String className = it.next();
            reflectiveNew(className);
        }
    }

    private void reflectiveNew(String className) {
        try {
            Class<? extends U> asSubclass = Class.forName(className, false, Recreator.class.getClassLoader()).asSubclass(SavedStateRegistry.AutoRecreated.class);
            try {
                Constructor declaredConstructor = asSubclass.getDeclaredConstructor(new Class[0]);
                declaredConstructor.setAccessible(true);
                try {
                    SavedStateRegistry.AutoRecreated newInstance = (SavedStateRegistry.AutoRecreated) declaredConstructor.newInstance(new Object[0]);
                    newInstance.onRecreated(this.mOwner);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to instantiate " + className, e);
                }
            } catch (NoSuchMethodException e2) {
                throw new IllegalStateException("Class" + asSubclass.getSimpleName() + " must have default constructor in order to be automatically recreated", e2);
            }
        } catch (ClassNotFoundException e3) {
            throw new RuntimeException("Class " + className + " wasn't found", e3);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class SavedStateProvider implements SavedStateRegistry.SavedStateProvider {
        final Set<String> mClasses = new HashSet();

        /* JADX INFO: Access modifiers changed from: package-private */
        public SavedStateProvider(SavedStateRegistry registry) {
            registry.registerSavedStateProvider(Recreator.COMPONENT_KEY, this);
        }

        @Override // androidx.savedstate.SavedStateRegistry.SavedStateProvider
        public Bundle saveState() {
            Bundle bundle = new Bundle();
            bundle.putStringArrayList(Recreator.CLASSES_KEY, new ArrayList<>(this.mClasses));
            return bundle;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void add(String className) {
            this.mClasses.add(className);
        }
    }
}
