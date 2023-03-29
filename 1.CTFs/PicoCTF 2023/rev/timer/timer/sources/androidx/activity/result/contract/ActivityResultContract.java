package androidx.activity.result.contract;

import android.content.Context;
import android.content.Intent;
/* loaded from: classes.dex */
public abstract class ActivityResultContract<I, O> {
    public abstract Intent createIntent(Context context, I i);

    public abstract O parseResult(int i, Intent intent);

    public SynchronousResult<O> getSynchronousResult(Context context, I input) {
        return null;
    }

    /* loaded from: classes.dex */
    public static final class SynchronousResult<T> {
        private final T mValue;

        public SynchronousResult(T value) {
            this.mValue = value;
        }

        public T getValue() {
            return this.mValue;
        }
    }
}
