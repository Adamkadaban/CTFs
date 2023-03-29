package androidx.savedstate;

import androidx.lifecycle.LifecycleOwner;
/* loaded from: classes.dex */
public interface SavedStateRegistryOwner extends LifecycleOwner {
    SavedStateRegistry getSavedStateRegistry();
}
