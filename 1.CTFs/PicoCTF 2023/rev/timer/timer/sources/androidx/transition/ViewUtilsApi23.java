package androidx.transition;

import android.os.Build;
import android.view.View;
/* loaded from: classes.dex */
class ViewUtilsApi23 extends ViewUtilsApi22 {
    private static boolean sTryHiddenSetTransitionVisibility = true;

    @Override // androidx.transition.ViewUtilsBase
    public void setTransitionVisibility(View view, int visibility) {
        if (Build.VERSION.SDK_INT == 28) {
            super.setTransitionVisibility(view, visibility);
        } else if (sTryHiddenSetTransitionVisibility) {
            try {
                view.setTransitionVisibility(visibility);
            } catch (NoSuchMethodError e) {
                sTryHiddenSetTransitionVisibility = false;
            }
        }
    }
}
