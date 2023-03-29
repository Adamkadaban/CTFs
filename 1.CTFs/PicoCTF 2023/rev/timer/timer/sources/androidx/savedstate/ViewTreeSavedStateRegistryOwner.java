package androidx.savedstate;

import android.view.View;
import android.view.ViewParent;
/* loaded from: classes.dex */
public final class ViewTreeSavedStateRegistryOwner {
    private ViewTreeSavedStateRegistryOwner() {
    }

    public static void set(View view, SavedStateRegistryOwner owner) {
        view.setTag(R.id.view_tree_saved_state_registry_owner, owner);
    }

    public static SavedStateRegistryOwner get(View view) {
        SavedStateRegistryOwner found = (SavedStateRegistryOwner) view.getTag(R.id.view_tree_saved_state_registry_owner);
        if (found != null) {
            return found;
        }
        ViewParent parent = view.getParent();
        while (found == null && (parent instanceof View)) {
            View parentView = (View) parent;
            found = (SavedStateRegistryOwner) parentView.getTag(R.id.view_tree_saved_state_registry_owner);
            parent = parentView.getParent();
        }
        return found;
    }
}
