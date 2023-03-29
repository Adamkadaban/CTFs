package androidx.transition;

import android.graphics.Matrix;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
/* loaded from: classes.dex */
class GhostViewUtils {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static GhostView addGhost(View view, ViewGroup viewGroup, Matrix matrix) {
        if (Build.VERSION.SDK_INT == 28) {
            return GhostViewPlatform.addGhost(view, viewGroup, matrix);
        }
        return GhostViewPort.addGhost(view, viewGroup, matrix);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void removeGhost(View view) {
        if (Build.VERSION.SDK_INT == 28) {
            GhostViewPlatform.removeGhost(view);
        } else {
            GhostViewPort.removeGhost(view);
        }
    }

    private GhostViewUtils() {
    }
}
