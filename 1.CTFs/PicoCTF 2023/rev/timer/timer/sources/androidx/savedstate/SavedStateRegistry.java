package androidx.savedstate;

import android.os.Bundle;
import androidx.arch.core.internal.SafeIterableMap;
import androidx.lifecycle.GenericLifecycleObserver;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleOwner;
import androidx.savedstate.Recreator;
import java.util.Iterator;
import java.util.Map;
/* loaded from: classes.dex */
public final class SavedStateRegistry {
    private static final String SAVED_COMPONENTS_KEY = "androidx.lifecycle.BundlableSavedStateRegistry.key";
    private Recreator.SavedStateProvider mRecreatorProvider;
    private boolean mRestored;
    private Bundle mRestoredState;
    private SafeIterableMap<String, SavedStateProvider> mComponents = new SafeIterableMap<>();
    boolean mAllowingSavingState = true;

    /* loaded from: classes.dex */
    public interface AutoRecreated {
        void onRecreated(SavedStateRegistryOwner savedStateRegistryOwner);
    }

    /* loaded from: classes.dex */
    public interface SavedStateProvider {
        Bundle saveState();
    }

    public Bundle consumeRestoredStateForKey(String key) {
        if (!this.mRestored) {
            throw new IllegalStateException("You can consumeRestoredStateForKey only after super.onCreate of corresponding component");
        }
        Bundle bundle = this.mRestoredState;
        if (bundle != null) {
            Bundle result = bundle.getBundle(key);
            this.mRestoredState.remove(key);
            if (this.mRestoredState.isEmpty()) {
                this.mRestoredState = null;
            }
            return result;
        }
        return null;
    }

    public void registerSavedStateProvider(String key, SavedStateProvider provider) {
        SavedStateProvider previous = this.mComponents.putIfAbsent(key, provider);
        if (previous != null) {
            throw new IllegalArgumentException("SavedStateProvider with the given key is already registered");
        }
    }

    public void unregisterSavedStateProvider(String key) {
        this.mComponents.remove(key);
    }

    public boolean isRestored() {
        return this.mRestored;
    }

    public void runOnNextRecreation(Class<? extends AutoRecreated> clazz) {
        if (!this.mAllowingSavingState) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
        if (this.mRecreatorProvider == null) {
            this.mRecreatorProvider = new Recreator.SavedStateProvider(this);
        }
        try {
            clazz.getDeclaredConstructor(new Class[0]);
            this.mRecreatorProvider.add(clazz.getName());
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("Class" + clazz.getSimpleName() + " must have default constructor in order to be automatically recreated", e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performRestore(Lifecycle lifecycle, Bundle savedState) {
        if (this.mRestored) {
            throw new IllegalStateException("SavedStateRegistry was already restored.");
        }
        if (savedState != null) {
            this.mRestoredState = savedState.getBundle(SAVED_COMPONENTS_KEY);
        }
        lifecycle.addObserver(new GenericLifecycleObserver() { // from class: androidx.savedstate.SavedStateRegistry.1
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                if (event == Lifecycle.Event.ON_START) {
                    SavedStateRegistry.this.mAllowingSavingState = true;
                } else if (event == Lifecycle.Event.ON_STOP) {
                    SavedStateRegistry.this.mAllowingSavingState = false;
                }
            }
        });
        this.mRestored = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performSave(Bundle outBundle) {
        Bundle components = new Bundle();
        Bundle bundle = this.mRestoredState;
        if (bundle != null) {
            components.putAll(bundle);
        }
        Iterator<Map.Entry<String, SavedStateProvider>> it = this.mComponents.iteratorWithAdditions();
        while (it.hasNext()) {
            Map.Entry<String, SavedStateProvider> entry1 = it.next();
            components.putBundle(entry1.getKey(), entry1.getValue().saveState());
        }
        outBundle.putBundle(SAVED_COMPONENTS_KEY, components);
    }
}
