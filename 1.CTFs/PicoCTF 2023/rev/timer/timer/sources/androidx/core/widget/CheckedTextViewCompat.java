package androidx.core.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.Log;
import android.widget.CheckedTextView;
import java.lang.reflect.Field;
/* loaded from: classes.dex */
public final class CheckedTextViewCompat {
    private static final String TAG = "CheckedTextViewCompat";

    private CheckedTextViewCompat() {
    }

    public static void setCheckMarkTintList(CheckedTextView textView, ColorStateList tint) {
        if (Build.VERSION.SDK_INT >= 21) {
            Api21Impl.setCheckMarkTintList(textView, tint);
        } else if (textView instanceof TintableCheckedTextView) {
            ((TintableCheckedTextView) textView).setSupportCheckMarkTintList(tint);
        }
    }

    public static ColorStateList getCheckMarkTintList(CheckedTextView textView) {
        if (Build.VERSION.SDK_INT >= 21) {
            return Api21Impl.getCheckMarkTintList(textView);
        }
        if (textView instanceof TintableCheckedTextView) {
            return ((TintableCheckedTextView) textView).getSupportCheckMarkTintList();
        }
        return null;
    }

    public static void setCheckMarkTintMode(CheckedTextView textView, PorterDuff.Mode tintMode) {
        if (Build.VERSION.SDK_INT >= 21) {
            Api21Impl.setCheckMarkTintMode(textView, tintMode);
        } else if (textView instanceof TintableCheckedTextView) {
            ((TintableCheckedTextView) textView).setSupportCheckMarkTintMode(tintMode);
        }
    }

    public static PorterDuff.Mode getCheckMarkTintMode(CheckedTextView textView) {
        if (Build.VERSION.SDK_INT >= 21) {
            return Api21Impl.getCheckMarkTintMode(textView);
        }
        if (textView instanceof TintableCheckedTextView) {
            return ((TintableCheckedTextView) textView).getSupportCheckMarkTintMode();
        }
        return null;
    }

    public static Drawable getCheckMarkDrawable(CheckedTextView textView) {
        if (Build.VERSION.SDK_INT >= 16) {
            return Api16Impl.getCheckMarkDrawable(textView);
        }
        return Api14Impl.getCheckMarkDrawable(textView);
    }

    /* loaded from: classes.dex */
    private static class Api21Impl {
        private Api21Impl() {
        }

        static void setCheckMarkTintList(CheckedTextView textView, ColorStateList tint) {
            textView.setCheckMarkTintList(tint);
        }

        static ColorStateList getCheckMarkTintList(CheckedTextView textView) {
            return textView.getCheckMarkTintList();
        }

        static void setCheckMarkTintMode(CheckedTextView textView, PorterDuff.Mode tintMode) {
            textView.setCheckMarkTintMode(tintMode);
        }

        static PorterDuff.Mode getCheckMarkTintMode(CheckedTextView textView) {
            return textView.getCheckMarkTintMode();
        }
    }

    /* loaded from: classes.dex */
    private static class Api16Impl {
        private Api16Impl() {
        }

        static Drawable getCheckMarkDrawable(CheckedTextView textView) {
            return textView.getCheckMarkDrawable();
        }
    }

    /* loaded from: classes.dex */
    private static class Api14Impl {
        private static Field sCheckMarkDrawableField;
        private static boolean sResolved;

        private Api14Impl() {
        }

        static Drawable getCheckMarkDrawable(CheckedTextView textView) {
            if (!sResolved) {
                try {
                    Field declaredField = CheckedTextView.class.getDeclaredField("mCheckMarkDrawable");
                    sCheckMarkDrawableField = declaredField;
                    declaredField.setAccessible(true);
                } catch (NoSuchFieldException e) {
                    Log.i(CheckedTextViewCompat.TAG, "Failed to retrieve mCheckMarkDrawable field", e);
                }
                sResolved = true;
            }
            Field field = sCheckMarkDrawableField;
            if (field != null) {
                try {
                    return (Drawable) field.get(textView);
                } catch (IllegalAccessException e2) {
                    Log.i(CheckedTextViewCompat.TAG, "Failed to get check mark drawable via reflection", e2);
                    sCheckMarkDrawableField = null;
                }
            }
            return null;
        }
    }
}
