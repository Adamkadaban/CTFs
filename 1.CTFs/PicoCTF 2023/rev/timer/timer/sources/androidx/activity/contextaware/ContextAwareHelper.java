package androidx.activity.contextaware;

import android.content.Context;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
/* loaded from: classes.dex */
public final class ContextAwareHelper {
    private volatile Context mContext;
    private final Set<OnContextAvailableListener> mListeners = new CopyOnWriteArraySet();

    public Context peekAvailableContext() {
        return this.mContext;
    }

    public void addOnContextAvailableListener(OnContextAvailableListener listener) {
        if (this.mContext != null) {
            listener.onContextAvailable(this.mContext);
        }
        this.mListeners.add(listener);
    }

    public void removeOnContextAvailableListener(OnContextAvailableListener listener) {
        this.mListeners.remove(listener);
    }

    public void dispatchOnContextAvailable(Context context) {
        this.mContext = context;
        for (OnContextAvailableListener listener : this.mListeners) {
            listener.onContextAvailable(context);
        }
    }

    public void clearAvailableContext() {
        this.mContext = null;
    }
}
