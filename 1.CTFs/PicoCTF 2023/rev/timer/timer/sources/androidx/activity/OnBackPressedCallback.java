package androidx.activity;

import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
/* loaded from: classes.dex */
public abstract class OnBackPressedCallback {
    private CopyOnWriteArrayList<Cancellable> mCancellables = new CopyOnWriteArrayList<>();
    private boolean mEnabled;

    public abstract void handleOnBackPressed();

    public OnBackPressedCallback(boolean enabled) {
        this.mEnabled = enabled;
    }

    public final void setEnabled(boolean enabled) {
        this.mEnabled = enabled;
    }

    public final boolean isEnabled() {
        return this.mEnabled;
    }

    public final void remove() {
        Iterator<Cancellable> it = this.mCancellables.iterator();
        while (it.hasNext()) {
            Cancellable cancellable = it.next();
            cancellable.cancel();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addCancellable(Cancellable cancellable) {
        this.mCancellables.add(cancellable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeCancellable(Cancellable cancellable) {
        this.mCancellables.remove(cancellable);
    }
}
