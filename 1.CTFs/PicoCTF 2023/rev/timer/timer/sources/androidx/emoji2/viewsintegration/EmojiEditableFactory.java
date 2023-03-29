package androidx.emoji2.viewsintegration;

import android.text.Editable;
import androidx.emoji2.text.SpannableBuilder;
/* loaded from: classes.dex */
final class EmojiEditableFactory extends Editable.Factory {
    private static final Object INSTANCE_LOCK = new Object();
    private static volatile Editable.Factory sInstance;
    private static Class<?> sWatcherClass;

    private EmojiEditableFactory() {
        try {
            sWatcherClass = Class.forName("android.text.DynamicLayout$ChangeWatcher", false, getClass().getClassLoader());
        } catch (Throwable th) {
        }
    }

    public static Editable.Factory getInstance() {
        if (sInstance == null) {
            synchronized (INSTANCE_LOCK) {
                if (sInstance == null) {
                    sInstance = new EmojiEditableFactory();
                }
            }
        }
        return sInstance;
    }

    @Override // android.text.Editable.Factory
    public Editable newEditable(CharSequence source) {
        Class<?> cls = sWatcherClass;
        if (cls != null) {
            return SpannableBuilder.create(cls, source);
        }
        return super.newEditable(source);
    }
}
