package androidx.appcompat.content.res;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import androidx.appcompat.widget.ResourceManagerInternal;
import androidx.core.content.ContextCompat;
/* loaded from: classes.dex */
public final class AppCompatResources {
    private AppCompatResources() {
    }

    public static ColorStateList getColorStateList(Context context, int resId) {
        return ContextCompat.getColorStateList(context, resId);
    }

    public static Drawable getDrawable(Context context, int resId) {
        return ResourceManagerInternal.get().getDrawable(context, resId);
    }
}
