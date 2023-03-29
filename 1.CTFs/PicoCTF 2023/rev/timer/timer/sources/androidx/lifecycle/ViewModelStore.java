package androidx.lifecycle;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public class ViewModelStore {
    private final HashMap<String, ViewModel> mMap = new HashMap<>();

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void put(String key, ViewModel viewModel) {
        ViewModel oldViewModel = this.mMap.put(key, viewModel);
        if (oldViewModel != null) {
            oldViewModel.onCleared();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final ViewModel get(String key) {
        return this.mMap.get(key);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Set<String> keys() {
        return new HashSet(this.mMap.keySet());
    }

    public final void clear() {
        for (ViewModel vm : this.mMap.values()) {
            vm.clear();
        }
        this.mMap.clear();
    }
}
