package androidx.constraintlayout.widget;

import android.util.SparseIntArray;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
/* loaded from: classes.dex */
public class SharedValues {
    public static final int UNSET = -1;
    private SparseIntArray mValues = new SparseIntArray();
    private HashMap<Integer, HashSet<WeakReference<SharedValuesListener>>> mValuesListeners = new HashMap<>();

    /* loaded from: classes.dex */
    public interface SharedValuesListener {
        void onNewValue(int key, int newValue, int oldValue);
    }

    public void addListener(int key, SharedValuesListener listener) {
        HashSet<WeakReference<SharedValuesListener>> listeners = this.mValuesListeners.get(Integer.valueOf(key));
        if (listeners == null) {
            listeners = new HashSet<>();
            this.mValuesListeners.put(Integer.valueOf(key), listeners);
        }
        listeners.add(new WeakReference<>(listener));
    }

    public void removeListener(int key, SharedValuesListener listener) {
        HashSet<WeakReference<SharedValuesListener>> listeners = this.mValuesListeners.get(Integer.valueOf(key));
        if (listeners == null) {
            return;
        }
        List<WeakReference<SharedValuesListener>> toRemove = new ArrayList<>();
        Iterator<WeakReference<SharedValuesListener>> it = listeners.iterator();
        while (it.hasNext()) {
            WeakReference<SharedValuesListener> listenerWeakReference = it.next();
            SharedValuesListener l = listenerWeakReference.get();
            if (l == null || l == listener) {
                toRemove.add(listenerWeakReference);
            }
        }
        listeners.removeAll(toRemove);
    }

    public void removeListener(SharedValuesListener listener) {
        for (Integer key : this.mValuesListeners.keySet()) {
            removeListener(key.intValue(), listener);
        }
    }

    public void clearListeners() {
        this.mValuesListeners.clear();
    }

    public int getValue(int key) {
        return this.mValues.get(key, -1);
    }

    public void fireNewValue(int key, int value) {
        boolean needsCleanup = false;
        int previousValue = this.mValues.get(key, -1);
        if (previousValue == value) {
            return;
        }
        this.mValues.put(key, value);
        HashSet<WeakReference<SharedValuesListener>> listeners = this.mValuesListeners.get(Integer.valueOf(key));
        if (listeners == null) {
            return;
        }
        Iterator<WeakReference<SharedValuesListener>> it = listeners.iterator();
        while (it.hasNext()) {
            SharedValuesListener l = it.next().get();
            if (l != null) {
                l.onNewValue(key, value, previousValue);
            } else {
                needsCleanup = true;
            }
        }
        if (needsCleanup) {
            List<WeakReference<SharedValuesListener>> toRemove = new ArrayList<>();
            Iterator<WeakReference<SharedValuesListener>> it2 = listeners.iterator();
            while (it2.hasNext()) {
                WeakReference<SharedValuesListener> listenerWeakReference = it2.next();
                SharedValuesListener listener = listenerWeakReference.get();
                if (listener == null) {
                    toRemove.add(listenerWeakReference);
                }
            }
            listeners.removeAll(toRemove);
        }
    }
}
