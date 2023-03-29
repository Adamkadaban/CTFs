package androidx.recyclerview.widget;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityNodeProviderCompat;
import java.util.Map;
import java.util.WeakHashMap;
/* loaded from: classes.dex */
public class RecyclerViewAccessibilityDelegate extends AccessibilityDelegateCompat {
    private final ItemDelegate mItemDelegate;
    final RecyclerView mRecyclerView;

    public RecyclerViewAccessibilityDelegate(RecyclerView recyclerView) {
        this.mRecyclerView = recyclerView;
        AccessibilityDelegateCompat itemDelegate = getItemDelegate();
        if (itemDelegate != null && (itemDelegate instanceof ItemDelegate)) {
            this.mItemDelegate = (ItemDelegate) itemDelegate;
        } else {
            this.mItemDelegate = new ItemDelegate(this);
        }
    }

    boolean shouldIgnore() {
        return this.mRecyclerView.hasPendingAdapterUpdates();
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public boolean performAccessibilityAction(View host, int action, Bundle args) {
        if (super.performAccessibilityAction(host, action, args)) {
            return true;
        }
        if (!shouldIgnore() && this.mRecyclerView.getLayoutManager() != null) {
            return this.mRecyclerView.getLayoutManager().performAccessibilityAction(action, args);
        }
        return false;
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
        super.onInitializeAccessibilityNodeInfo(host, info);
        if (!shouldIgnore() && this.mRecyclerView.getLayoutManager() != null) {
            this.mRecyclerView.getLayoutManager().onInitializeAccessibilityNodeInfo(info);
        }
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
        super.onInitializeAccessibilityEvent(host, event);
        if ((host instanceof RecyclerView) && !shouldIgnore()) {
            RecyclerView rv = (RecyclerView) host;
            if (rv.getLayoutManager() != null) {
                rv.getLayoutManager().onInitializeAccessibilityEvent(event);
            }
        }
    }

    public AccessibilityDelegateCompat getItemDelegate() {
        return this.mItemDelegate;
    }

    /* loaded from: classes.dex */
    public static class ItemDelegate extends AccessibilityDelegateCompat {
        private Map<View, AccessibilityDelegateCompat> mOriginalItemDelegates = new WeakHashMap();
        final RecyclerViewAccessibilityDelegate mRecyclerViewDelegate;

        public ItemDelegate(RecyclerViewAccessibilityDelegate recyclerViewDelegate) {
            this.mRecyclerViewDelegate = recyclerViewDelegate;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void saveOriginalDelegate(View itemView) {
            AccessibilityDelegateCompat delegate = ViewCompat.getAccessibilityDelegate(itemView);
            if (delegate != null && delegate != this) {
                this.mOriginalItemDelegates.put(itemView, delegate);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public AccessibilityDelegateCompat getAndRemoveOriginalDelegateForItem(View itemView) {
            return this.mOriginalItemDelegates.remove(itemView);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            if (!this.mRecyclerViewDelegate.shouldIgnore() && this.mRecyclerViewDelegate.mRecyclerView.getLayoutManager() != null) {
                this.mRecyclerViewDelegate.mRecyclerView.getLayoutManager().onInitializeAccessibilityNodeInfoForItem(host, info);
                AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
                if (originalDelegate != null) {
                    originalDelegate.onInitializeAccessibilityNodeInfo(host, info);
                    return;
                } else {
                    super.onInitializeAccessibilityNodeInfo(host, info);
                    return;
                }
            }
            super.onInitializeAccessibilityNodeInfo(host, info);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public boolean performAccessibilityAction(View host, int action, Bundle args) {
            if (!this.mRecyclerViewDelegate.shouldIgnore() && this.mRecyclerViewDelegate.mRecyclerView.getLayoutManager() != null) {
                AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
                if (originalDelegate != null) {
                    if (originalDelegate.performAccessibilityAction(host, action, args)) {
                        return true;
                    }
                } else if (super.performAccessibilityAction(host, action, args)) {
                    return true;
                }
                return this.mRecyclerViewDelegate.mRecyclerView.getLayoutManager().performAccessibilityActionForItem(host, action, args);
            }
            return super.performAccessibilityAction(host, action, args);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void sendAccessibilityEvent(View host, int eventType) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                originalDelegate.sendAccessibilityEvent(host, eventType);
            } else {
                super.sendAccessibilityEvent(host, eventType);
            }
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void sendAccessibilityEventUnchecked(View host, AccessibilityEvent event) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                originalDelegate.sendAccessibilityEventUnchecked(host, event);
            } else {
                super.sendAccessibilityEventUnchecked(host, event);
            }
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                return originalDelegate.dispatchPopulateAccessibilityEvent(host, event);
            }
            return super.dispatchPopulateAccessibilityEvent(host, event);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                originalDelegate.onPopulateAccessibilityEvent(host, event);
            } else {
                super.onPopulateAccessibilityEvent(host, event);
            }
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                originalDelegate.onInitializeAccessibilityEvent(host, event);
            } else {
                super.onInitializeAccessibilityEvent(host, event);
            }
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                return originalDelegate.onRequestSendAccessibilityEvent(host, child, event);
            }
            return super.onRequestSendAccessibilityEvent(host, child, event);
        }

        @Override // androidx.core.view.AccessibilityDelegateCompat
        public AccessibilityNodeProviderCompat getAccessibilityNodeProvider(View host) {
            AccessibilityDelegateCompat originalDelegate = this.mOriginalItemDelegates.get(host);
            if (originalDelegate != null) {
                return originalDelegate.getAccessibilityNodeProvider(host);
            }
            return super.getAccessibilityNodeProvider(host);
        }
    }
}
