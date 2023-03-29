package androidx.core.database;

import android.database.CursorWindow;
import android.os.Build;
/* loaded from: classes.dex */
public final class CursorWindowCompat {
    private CursorWindowCompat() {
    }

    public static CursorWindow create(String name, long windowSizeBytes) {
        if (Build.VERSION.SDK_INT >= 28) {
            return new CursorWindow(name, windowSizeBytes);
        }
        if (Build.VERSION.SDK_INT >= 15) {
            return new CursorWindow(name);
        }
        return new CursorWindow(false);
    }
}
