package androidx.transition;

import android.view.View;
import android.view.WindowId;
/* loaded from: classes.dex */
class WindowIdApi18 implements WindowIdImpl {
    private final WindowId mWindowId;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WindowIdApi18(View view) {
        this.mWindowId = view.getWindowId();
    }

    public boolean equals(Object o) {
        return (o instanceof WindowIdApi18) && ((WindowIdApi18) o).mWindowId.equals(this.mWindowId);
    }

    public int hashCode() {
        return this.mWindowId.hashCode();
    }
}
