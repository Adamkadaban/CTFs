package androidx.fragment.app;

import androidx.lifecycle.ViewModelStore;
import java.util.Collection;
import java.util.Map;
@Deprecated
/* loaded from: classes.dex */
public class FragmentManagerNonConfig {
    private final Map<String, FragmentManagerNonConfig> mChildNonConfigs;
    private final Collection<Fragment> mFragments;
    private final Map<String, ViewModelStore> mViewModelStores;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentManagerNonConfig(Collection<Fragment> fragments, Map<String, FragmentManagerNonConfig> childNonConfigs, Map<String, ViewModelStore> viewModelStores) {
        this.mFragments = fragments;
        this.mChildNonConfigs = childNonConfigs;
        this.mViewModelStores = viewModelStores;
    }

    boolean isRetaining(Fragment f) {
        Collection<Fragment> collection = this.mFragments;
        if (collection == null) {
            return false;
        }
        return collection.contains(f);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Collection<Fragment> getFragments() {
        return this.mFragments;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Map<String, FragmentManagerNonConfig> getChildNonConfigs() {
        return this.mChildNonConfigs;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Map<String, ViewModelStore> getViewModelStores() {
        return this.mViewModelStores;
    }
}
