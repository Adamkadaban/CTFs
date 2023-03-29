package androidx.transition;

import android.graphics.Matrix;
import android.view.View;
/* loaded from: classes.dex */
class ViewUtilsApi21 extends ViewUtilsApi19 {
    private static boolean sTryHiddenSetAnimationMatrix = true;
    private static boolean sTryHiddenTransformMatrixToGlobal = true;
    private static boolean sTryHiddenTransformMatrixToLocal = true;

    @Override // androidx.transition.ViewUtilsBase
    public void transformMatrixToGlobal(View view, Matrix matrix) {
        if (sTryHiddenTransformMatrixToGlobal) {
            try {
                view.transformMatrixToGlobal(matrix);
            } catch (NoSuchMethodError e) {
                sTryHiddenTransformMatrixToGlobal = false;
            }
        }
    }

    @Override // androidx.transition.ViewUtilsBase
    public void transformMatrixToLocal(View view, Matrix matrix) {
        if (sTryHiddenTransformMatrixToLocal) {
            try {
                view.transformMatrixToLocal(matrix);
            } catch (NoSuchMethodError e) {
                sTryHiddenTransformMatrixToLocal = false;
            }
        }
    }

    @Override // androidx.transition.ViewUtilsBase
    public void setAnimationMatrix(View view, Matrix matrix) {
        if (sTryHiddenSetAnimationMatrix) {
            try {
                view.setAnimationMatrix(matrix);
            } catch (NoSuchMethodError e) {
                sTryHiddenSetAnimationMatrix = false;
            }
        }
    }
}
