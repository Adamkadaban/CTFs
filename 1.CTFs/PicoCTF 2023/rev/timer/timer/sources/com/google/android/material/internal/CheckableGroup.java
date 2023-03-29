package com.google.android.material.internal;

import android.view.View;
import android.view.ViewGroup;
import com.google.android.material.internal.MaterialCheckable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public class CheckableGroup<T extends MaterialCheckable<T>> {
    private final Map<Integer, T> checkables = new HashMap();
    private final Set<Integer> checkedIds = new HashSet();
    private OnCheckedStateChangeListener onCheckedStateChangeListener;
    private boolean selectionRequired;
    private boolean singleSelection;

    /* loaded from: classes.dex */
    public interface OnCheckedStateChangeListener {
        void onCheckedStateChanged(Set<Integer> set);
    }

    public void setSingleSelection(boolean singleSelection) {
        if (this.singleSelection != singleSelection) {
            this.singleSelection = singleSelection;
            clearCheck();
        }
    }

    public boolean isSingleSelection() {
        return this.singleSelection;
    }

    public void setSelectionRequired(boolean selectionRequired) {
        this.selectionRequired = selectionRequired;
    }

    public boolean isSelectionRequired() {
        return this.selectionRequired;
    }

    public void setOnCheckedStateChangeListener(OnCheckedStateChangeListener listener) {
        this.onCheckedStateChangeListener = listener;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void addCheckable(T checkable) {
        this.checkables.put(Integer.valueOf(checkable.getId()), checkable);
        if (checkable.isChecked()) {
            checkInternal(checkable);
        }
        checkable.setInternalOnCheckedChangeListener(new MaterialCheckable.OnCheckedChangeListener<T>() { // from class: com.google.android.material.internal.CheckableGroup.1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // com.google.android.material.internal.MaterialCheckable.OnCheckedChangeListener
            public /* bridge */ /* synthetic */ void onCheckedChanged(Object obj, boolean z) {
                onCheckedChanged((AnonymousClass1) ((MaterialCheckable) obj), z);
            }

            public void onCheckedChanged(T checkable2, boolean isChecked) {
                CheckableGroup checkableGroup = CheckableGroup.this;
                if (isChecked) {
                    if (!checkableGroup.checkInternal(checkable2)) {
                        return;
                    }
                } else if (!checkableGroup.uncheckInternal(checkable2, checkableGroup.selectionRequired)) {
                    return;
                }
                CheckableGroup.this.onCheckedStateChanged();
            }
        });
    }

    public void removeCheckable(T checkable) {
        checkable.setInternalOnCheckedChangeListener(null);
        this.checkables.remove(Integer.valueOf(checkable.getId()));
        this.checkedIds.remove(Integer.valueOf(checkable.getId()));
    }

    public void check(int id) {
        T checkable = this.checkables.get(Integer.valueOf(id));
        if (checkable != null && checkInternal(checkable)) {
            onCheckedStateChanged();
        }
    }

    public void uncheck(int id) {
        T checkable = this.checkables.get(Integer.valueOf(id));
        if (checkable != null && uncheckInternal(checkable, this.selectionRequired)) {
            onCheckedStateChanged();
        }
    }

    public void clearCheck() {
        boolean checkedStateChanged = !this.checkedIds.isEmpty();
        for (T checkable : this.checkables.values()) {
            uncheckInternal(checkable, false);
        }
        if (checkedStateChanged) {
            onCheckedStateChanged();
        }
    }

    public int getSingleCheckedId() {
        if (!this.singleSelection || this.checkedIds.isEmpty()) {
            return -1;
        }
        return this.checkedIds.iterator().next().intValue();
    }

    public Set<Integer> getCheckedIds() {
        return new HashSet(this.checkedIds);
    }

    public List<Integer> getCheckedIdsSortedByChildOrder(ViewGroup parent) {
        Set<Integer> checkedIds = getCheckedIds();
        List<Integer> sortedCheckedIds = new ArrayList<>();
        for (int i = 0; i < parent.getChildCount(); i++) {
            View child = parent.getChildAt(i);
            if ((child instanceof MaterialCheckable) && checkedIds.contains(Integer.valueOf(child.getId()))) {
                sortedCheckedIds.add(Integer.valueOf(child.getId()));
            }
        }
        return sortedCheckedIds;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkInternal(MaterialCheckable<T> checkable) {
        int id = checkable.getId();
        if (this.checkedIds.contains(Integer.valueOf(id))) {
            return false;
        }
        T singleCheckedItem = this.checkables.get(Integer.valueOf(getSingleCheckedId()));
        if (singleCheckedItem != null) {
            uncheckInternal(singleCheckedItem, false);
        }
        boolean checkedStateChanged = this.checkedIds.add(Integer.valueOf(id));
        if (!checkable.isChecked()) {
            checkable.setChecked(true);
        }
        return checkedStateChanged;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean uncheckInternal(MaterialCheckable<T> checkable, boolean selectionRequired) {
        int id = checkable.getId();
        if (this.checkedIds.contains(Integer.valueOf(id))) {
            if (selectionRequired && this.checkedIds.size() == 1 && this.checkedIds.contains(Integer.valueOf(id))) {
                checkable.setChecked(true);
                return false;
            }
            boolean checkedStateChanged = this.checkedIds.remove(Integer.valueOf(id));
            if (checkable.isChecked()) {
                checkable.setChecked(false);
            }
            return checkedStateChanged;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onCheckedStateChanged() {
        OnCheckedStateChangeListener onCheckedStateChangeListener = this.onCheckedStateChangeListener;
        if (onCheckedStateChangeListener != null) {
            onCheckedStateChangeListener.onCheckedStateChanged(getCheckedIds());
        }
    }
}
