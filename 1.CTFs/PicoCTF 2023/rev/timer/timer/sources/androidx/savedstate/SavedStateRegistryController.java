package androidx.savedstate;

import android.os.Bundle;
import androidx.lifecycle.Lifecycle;
/* loaded from: classes.dex */
public final class SavedStateRegistryController {
    private final SavedStateRegistryOwner mOwner;
    private final SavedStateRegistry mRegistry = new SavedStateRegistry();

    private SavedStateRegistryController(SavedStateRegistryOwner owner) {
        this.mOwner = owner;
    }

    public SavedStateRegistry getSavedStateRegistry() {
        return this.mRegistry;
    }

    public void performRestore(Bundle savedState) {
        Lifecycle lifecycle = this.mOwner.getLifecycle();
        if (lifecycle.getCurrentState() != Lifecycle.State.INITIALIZED) {
            throw new IllegalStateException("Restarter must be created only during owner's initialization stage");
        }
        lifecycle.addObserver(new Recreator(this.mOwner));
        this.mRegistry.performRestore(lifecycle, savedState);
    }

    public void performSave(Bundle outBundle) {
        this.mRegistry.performSave(outBundle);
    }

    public static SavedStateRegistryController create(SavedStateRegistryOwner owner) {
        return new SavedStateRegistryController(owner);
    }
}
