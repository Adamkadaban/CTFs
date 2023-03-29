package com.google.android.material.datepicker;

import androidx.fragment.app.Fragment;
import java.util.LinkedHashSet;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public abstract class PickerFragment<S> extends Fragment {
    protected final LinkedHashSet<OnSelectionChangedListener<S>> onSelectionChangedListeners = new LinkedHashSet<>();

    abstract DateSelector<S> getDateSelector();

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean addOnSelectionChangedListener(OnSelectionChangedListener<S> listener) {
        return this.onSelectionChangedListeners.add(listener);
    }

    boolean removeOnSelectionChangedListener(OnSelectionChangedListener<S> listener) {
        return this.onSelectionChangedListeners.remove(listener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void clearOnSelectionChangedListeners() {
        this.onSelectionChangedListeners.clear();
    }
}
