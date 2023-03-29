package androidx.lifecycle;

import android.view.View;
import android.view.ViewParent;
import androidx.lifecycle.viewmodel.R;
/* loaded from: classes.dex */
public class ViewTreeViewModelStoreOwner {
    private ViewTreeViewModelStoreOwner() {
    }

    public static void set(View view, ViewModelStoreOwner viewModelStoreOwner) {
        view.setTag(R.id.view_tree_view_model_store_owner, viewModelStoreOwner);
    }

    public static ViewModelStoreOwner get(View view) {
        ViewModelStoreOwner found = (ViewModelStoreOwner) view.getTag(R.id.view_tree_view_model_store_owner);
        if (found != null) {
            return found;
        }
        ViewParent parent = view.getParent();
        while (found == null && (parent instanceof View)) {
            View parentView = (View) parent;
            found = (ViewModelStoreOwner) parentView.getTag(R.id.view_tree_view_model_store_owner);
            parent = parentView.getParent();
        }
        return found;
    }
}
