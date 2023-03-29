package com.google.android.material.internal;

import android.widget.Checkable;
import com.google.android.material.internal.MaterialCheckable;
/* loaded from: classes.dex */
public interface MaterialCheckable<T extends MaterialCheckable<T>> extends Checkable {

    /* loaded from: classes.dex */
    public interface OnCheckedChangeListener<C> {
        void onCheckedChanged(C c, boolean z);
    }

    int getId();

    void setInternalOnCheckedChangeListener(OnCheckedChangeListener<T> onCheckedChangeListener);
}
