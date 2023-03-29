package androidx.customview.widget;

import android.content.Context;
import android.graphics.Rect;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import androidx.collection.SparseArrayCompat;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityEventCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityNodeProviderCompat;
import androidx.core.view.accessibility.AccessibilityRecordCompat;
import androidx.customview.widget.FocusStrategy;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public abstract class ExploreByTouchHelper extends AccessibilityDelegateCompat {
    private static final String DEFAULT_CLASS_NAME = "android.view.View";
    public static final int HOST_ID = -1;
    public static final int INVALID_ID = Integer.MIN_VALUE;
    private static final Rect INVALID_PARENT_BOUNDS = new Rect(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MIN_VALUE, Integer.MIN_VALUE);
    private static final FocusStrategy.BoundsAdapter<AccessibilityNodeInfoCompat> NODE_ADAPTER = new FocusStrategy.BoundsAdapter<AccessibilityNodeInfoCompat>() { // from class: androidx.customview.widget.ExploreByTouchHelper.1
        @Override // androidx.customview.widget.FocusStrategy.BoundsAdapter
        public void obtainBounds(AccessibilityNodeInfoCompat node, Rect outBounds) {
            node.getBoundsInParent(outBounds);
        }
    };
    private static final FocusStrategy.CollectionAdapter<SparseArrayCompat<AccessibilityNodeInfoCompat>, AccessibilityNodeInfoCompat> SPARSE_VALUES_ADAPTER = new FocusStrategy.CollectionAdapter<SparseArrayCompat<AccessibilityNodeInfoCompat>, AccessibilityNodeInfoCompat>() { // from class: androidx.customview.widget.ExploreByTouchHelper.2
        @Override // androidx.customview.widget.FocusStrategy.CollectionAdapter
        public AccessibilityNodeInfoCompat get(SparseArrayCompat<AccessibilityNodeInfoCompat> collection, int index) {
            return collection.valueAt(index);
        }

        @Override // androidx.customview.widget.FocusStrategy.CollectionAdapter
        public int size(SparseArrayCompat<AccessibilityNodeInfoCompat> collection) {
            return collection.size();
        }
    };
    private final View mHost;
    private final AccessibilityManager mManager;
    private MyNodeProvider mNodeProvider;
    private final Rect mTempScreenRect = new Rect();
    private final Rect mTempParentRect = new Rect();
    private final Rect mTempVisibleRect = new Rect();
    private final int[] mTempGlobalRect = new int[2];
    int mAccessibilityFocusedVirtualViewId = Integer.MIN_VALUE;
    int mKeyboardFocusedVirtualViewId = Integer.MIN_VALUE;
    private int mHoveredVirtualViewId = Integer.MIN_VALUE;

    protected abstract int getVirtualViewAt(float f, float f2);

    protected abstract void getVisibleVirtualViews(List<Integer> list);

    protected abstract boolean onPerformActionForVirtualView(int i, int i2, Bundle bundle);

    protected abstract void onPopulateNodeForVirtualView(int i, AccessibilityNodeInfoCompat accessibilityNodeInfoCompat);

    public ExploreByTouchHelper(View host) {
        if (host == null) {
            throw new IllegalArgumentException("View may not be null");
        }
        this.mHost = host;
        Context context = host.getContext();
        this.mManager = (AccessibilityManager) context.getSystemService("accessibility");
        host.setFocusable(true);
        if (ViewCompat.getImportantForAccessibility(host) == 0) {
            ViewCompat.setImportantForAccessibility(host, 1);
        }
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public AccessibilityNodeProviderCompat getAccessibilityNodeProvider(View host) {
        if (this.mNodeProvider == null) {
            this.mNodeProvider = new MyNodeProvider();
        }
        return this.mNodeProvider;
    }

    public final boolean dispatchHoverEvent(MotionEvent event) {
        if (this.mManager.isEnabled() && this.mManager.isTouchExplorationEnabled()) {
            switch (event.getAction()) {
                case 7:
                case 9:
                    int virtualViewId = getVirtualViewAt(event.getX(), event.getY());
                    updateHoveredVirtualView(virtualViewId);
                    return virtualViewId != Integer.MIN_VALUE;
                case 8:
                default:
                    return false;
                case 10:
                    if (this.mHoveredVirtualViewId != Integer.MIN_VALUE) {
                        updateHoveredVirtualView(Integer.MIN_VALUE);
                        return true;
                    }
                    return false;
            }
        }
        return false;
    }

    public final boolean dispatchKeyEvent(KeyEvent event) {
        boolean handled = false;
        int action = event.getAction();
        if (action == 1) {
            return false;
        }
        int keyCode = event.getKeyCode();
        switch (keyCode) {
            case 19:
            case 20:
            case 21:
            case 22:
                if (!event.hasNoModifiers()) {
                    return false;
                }
                int direction = keyToDirection(keyCode);
                int count = event.getRepeatCount() + 1;
                for (int i = 0; i < count && moveFocus(direction, null); i++) {
                    handled = true;
                }
                return handled;
            case 23:
            case 66:
                if (!event.hasNoModifiers() || event.getRepeatCount() != 0) {
                    return false;
                }
                clickKeyboardFocusedVirtualView();
                return true;
            case 61:
                if (event.hasNoModifiers()) {
                    boolean handled2 = moveFocus(2, null);
                    return handled2;
                } else if (!event.hasModifiers(1)) {
                    return false;
                } else {
                    boolean handled3 = moveFocus(1, null);
                    return handled3;
                }
            default:
                return false;
        }
    }

    public final void onFocusChanged(boolean gainFocus, int direction, Rect previouslyFocusedRect) {
        int i = this.mKeyboardFocusedVirtualViewId;
        if (i != Integer.MIN_VALUE) {
            clearKeyboardFocusForVirtualView(i);
        }
        if (gainFocus) {
            moveFocus(direction, previouslyFocusedRect);
        }
    }

    public final int getAccessibilityFocusedVirtualViewId() {
        return this.mAccessibilityFocusedVirtualViewId;
    }

    public final int getKeyboardFocusedVirtualViewId() {
        return this.mKeyboardFocusedVirtualViewId;
    }

    private static int keyToDirection(int keyCode) {
        switch (keyCode) {
            case 19:
                return 33;
            case 20:
            default:
                return 130;
            case 21:
                return 17;
            case 22:
                return 66;
        }
    }

    private void getBoundsInParent(int virtualViewId, Rect outBounds) {
        AccessibilityNodeInfoCompat node = obtainAccessibilityNodeInfo(virtualViewId);
        node.getBoundsInParent(outBounds);
    }

    private boolean moveFocus(int direction, Rect previouslyFocusedRect) {
        AccessibilityNodeInfoCompat nextFocusedNode;
        int index;
        SparseArrayCompat<AccessibilityNodeInfoCompat> allNodes = getAllNodes();
        int focusedNodeId = this.mKeyboardFocusedVirtualViewId;
        AccessibilityNodeInfoCompat focusedNode = focusedNodeId == Integer.MIN_VALUE ? null : allNodes.get(focusedNodeId);
        switch (direction) {
            case 1:
            case 2:
                boolean isLayoutRtl = ViewCompat.getLayoutDirection(this.mHost) == 1;
                nextFocusedNode = (AccessibilityNodeInfoCompat) FocusStrategy.findNextFocusInRelativeDirection(allNodes, SPARSE_VALUES_ADAPTER, NODE_ADAPTER, focusedNode, direction, isLayoutRtl, false);
                break;
            case 17:
            case 33:
            case 66:
            case 130:
                Rect selectedRect = new Rect();
                int i = this.mKeyboardFocusedVirtualViewId;
                if (i != Integer.MIN_VALUE) {
                    getBoundsInParent(i, selectedRect);
                } else if (previouslyFocusedRect != null) {
                    selectedRect.set(previouslyFocusedRect);
                } else {
                    guessPreviouslyFocusedRect(this.mHost, direction, selectedRect);
                }
                nextFocusedNode = (AccessibilityNodeInfoCompat) FocusStrategy.findNextFocusInAbsoluteDirection(allNodes, SPARSE_VALUES_ADAPTER, NODE_ADAPTER, focusedNode, selectedRect, direction);
                break;
            default:
                throw new IllegalArgumentException("direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD, FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
        }
        if (nextFocusedNode == null) {
            index = Integer.MIN_VALUE;
        } else {
            int index2 = allNodes.indexOfValue(nextFocusedNode);
            index = allNodes.keyAt(index2);
        }
        return requestKeyboardFocusForVirtualView(index);
    }

    private SparseArrayCompat<AccessibilityNodeInfoCompat> getAllNodes() {
        List<Integer> virtualViewIds = new ArrayList<>();
        getVisibleVirtualViews(virtualViewIds);
        SparseArrayCompat<AccessibilityNodeInfoCompat> allNodes = new SparseArrayCompat<>();
        for (int virtualViewIdIndex = 0; virtualViewIdIndex < virtualViewIds.size(); virtualViewIdIndex++) {
            AccessibilityNodeInfoCompat virtualView = createNodeForChild(virtualViewIds.get(virtualViewIdIndex).intValue());
            allNodes.put(virtualViewIds.get(virtualViewIdIndex).intValue(), virtualView);
        }
        return allNodes;
    }

    private static Rect guessPreviouslyFocusedRect(View host, int direction, Rect outBounds) {
        int w = host.getWidth();
        int h = host.getHeight();
        switch (direction) {
            case 17:
                outBounds.set(w, 0, w, h);
                break;
            case 33:
                outBounds.set(0, h, w, h);
                break;
            case 66:
                outBounds.set(-1, 0, -1, h);
                break;
            case 130:
                outBounds.set(0, -1, w, -1);
                break;
            default:
                throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
        }
        return outBounds;
    }

    private boolean clickKeyboardFocusedVirtualView() {
        int i = this.mKeyboardFocusedVirtualViewId;
        return i != Integer.MIN_VALUE && onPerformActionForVirtualView(i, 16, null);
    }

    public final boolean sendEventForVirtualView(int virtualViewId, int eventType) {
        ViewParent parent;
        if (virtualViewId == Integer.MIN_VALUE || !this.mManager.isEnabled() || (parent = this.mHost.getParent()) == null) {
            return false;
        }
        AccessibilityEvent event = createEvent(virtualViewId, eventType);
        return parent.requestSendAccessibilityEvent(this.mHost, event);
    }

    public final void invalidateRoot() {
        invalidateVirtualView(-1, 1);
    }

    public final void invalidateVirtualView(int virtualViewId) {
        invalidateVirtualView(virtualViewId, 0);
    }

    public final void invalidateVirtualView(int virtualViewId, int changeTypes) {
        ViewParent parent;
        if (virtualViewId != Integer.MIN_VALUE && this.mManager.isEnabled() && (parent = this.mHost.getParent()) != null) {
            AccessibilityEvent event = createEvent(virtualViewId, 2048);
            AccessibilityEventCompat.setContentChangeTypes(event, changeTypes);
            parent.requestSendAccessibilityEvent(this.mHost, event);
        }
    }

    @Deprecated
    public int getFocusedVirtualView() {
        return getAccessibilityFocusedVirtualViewId();
    }

    protected void onVirtualViewKeyboardFocusChanged(int virtualViewId, boolean hasFocus) {
    }

    private void updateHoveredVirtualView(int virtualViewId) {
        if (this.mHoveredVirtualViewId == virtualViewId) {
            return;
        }
        int previousVirtualViewId = this.mHoveredVirtualViewId;
        this.mHoveredVirtualViewId = virtualViewId;
        sendEventForVirtualView(virtualViewId, 128);
        sendEventForVirtualView(previousVirtualViewId, 256);
    }

    private AccessibilityEvent createEvent(int virtualViewId, int eventType) {
        switch (virtualViewId) {
            case -1:
                return createEventForHost(eventType);
            default:
                return createEventForChild(virtualViewId, eventType);
        }
    }

    private AccessibilityEvent createEventForHost(int eventType) {
        AccessibilityEvent event = AccessibilityEvent.obtain(eventType);
        this.mHost.onInitializeAccessibilityEvent(event);
        return event;
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
        super.onInitializeAccessibilityEvent(host, event);
        onPopulateEventForHost(event);
    }

    private AccessibilityEvent createEventForChild(int virtualViewId, int eventType) {
        AccessibilityEvent event = AccessibilityEvent.obtain(eventType);
        AccessibilityNodeInfoCompat node = obtainAccessibilityNodeInfo(virtualViewId);
        event.getText().add(node.getText());
        event.setContentDescription(node.getContentDescription());
        event.setScrollable(node.isScrollable());
        event.setPassword(node.isPassword());
        event.setEnabled(node.isEnabled());
        event.setChecked(node.isChecked());
        onPopulateEventForVirtualView(virtualViewId, event);
        if (event.getText().isEmpty() && event.getContentDescription() == null) {
            throw new RuntimeException("Callbacks must add text or a content description in populateEventForVirtualViewId()");
        }
        event.setClassName(node.getClassName());
        AccessibilityRecordCompat.setSource(event, this.mHost, virtualViewId);
        event.setPackageName(this.mHost.getContext().getPackageName());
        return event;
    }

    AccessibilityNodeInfoCompat obtainAccessibilityNodeInfo(int virtualViewId) {
        if (virtualViewId == -1) {
            return createNodeForHost();
        }
        return createNodeForChild(virtualViewId);
    }

    private AccessibilityNodeInfoCompat createNodeForHost() {
        AccessibilityNodeInfoCompat info = AccessibilityNodeInfoCompat.obtain(this.mHost);
        ViewCompat.onInitializeAccessibilityNodeInfo(this.mHost, info);
        ArrayList<Integer> virtualViewIds = new ArrayList<>();
        getVisibleVirtualViews(virtualViewIds);
        int realNodeCount = info.getChildCount();
        if (realNodeCount > 0 && virtualViewIds.size() > 0) {
            throw new RuntimeException("Views cannot have both real and virtual children");
        }
        int count = virtualViewIds.size();
        for (int i = 0; i < count; i++) {
            info.addChild(this.mHost, virtualViewIds.get(i).intValue());
        }
        return info;
    }

    @Override // androidx.core.view.AccessibilityDelegateCompat
    public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
        super.onInitializeAccessibilityNodeInfo(host, info);
        onPopulateNodeForHost(info);
    }

    private AccessibilityNodeInfoCompat createNodeForChild(int virtualViewId) {
        AccessibilityNodeInfoCompat node = AccessibilityNodeInfoCompat.obtain();
        node.setEnabled(true);
        node.setFocusable(true);
        node.setClassName(DEFAULT_CLASS_NAME);
        Rect rect = INVALID_PARENT_BOUNDS;
        node.setBoundsInParent(rect);
        node.setBoundsInScreen(rect);
        node.setParent(this.mHost);
        onPopulateNodeForVirtualView(virtualViewId, node);
        if (node.getText() == null && node.getContentDescription() == null) {
            throw new RuntimeException("Callbacks must add text or a content description in populateNodeForVirtualViewId()");
        }
        node.getBoundsInParent(this.mTempParentRect);
        if (this.mTempParentRect.equals(rect)) {
            throw new RuntimeException("Callbacks must set parent bounds in populateNodeForVirtualViewId()");
        }
        int actions = node.getActions();
        if ((actions & 64) != 0) {
            throw new RuntimeException("Callbacks must not add ACTION_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()");
        }
        if ((actions & 128) != 0) {
            throw new RuntimeException("Callbacks must not add ACTION_CLEAR_ACCESSIBILITY_FOCUS in populateNodeForVirtualViewId()");
        }
        node.setPackageName(this.mHost.getContext().getPackageName());
        node.setSource(this.mHost, virtualViewId);
        if (this.mAccessibilityFocusedVirtualViewId == virtualViewId) {
            node.setAccessibilityFocused(true);
            node.addAction(128);
        } else {
            node.setAccessibilityFocused(false);
            node.addAction(64);
        }
        boolean isFocused = this.mKeyboardFocusedVirtualViewId == virtualViewId;
        if (isFocused) {
            node.addAction(2);
        } else if (node.isFocusable()) {
            node.addAction(1);
        }
        node.setFocused(isFocused);
        this.mHost.getLocationOnScreen(this.mTempGlobalRect);
        node.getBoundsInScreen(this.mTempScreenRect);
        if (this.mTempScreenRect.equals(rect)) {
            node.getBoundsInParent(this.mTempScreenRect);
            if (node.mParentVirtualDescendantId != -1) {
                AccessibilityNodeInfoCompat parentNode = AccessibilityNodeInfoCompat.obtain();
                for (int virtualDescendantId = node.mParentVirtualDescendantId; virtualDescendantId != -1; virtualDescendantId = parentNode.mParentVirtualDescendantId) {
                    parentNode.setParent(this.mHost, -1);
                    parentNode.setBoundsInParent(INVALID_PARENT_BOUNDS);
                    onPopulateNodeForVirtualView(virtualDescendantId, parentNode);
                    parentNode.getBoundsInParent(this.mTempParentRect);
                    this.mTempScreenRect.offset(this.mTempParentRect.left, this.mTempParentRect.top);
                }
                parentNode.recycle();
            }
            this.mTempScreenRect.offset(this.mTempGlobalRect[0] - this.mHost.getScrollX(), this.mTempGlobalRect[1] - this.mHost.getScrollY());
        }
        if (this.mHost.getLocalVisibleRect(this.mTempVisibleRect)) {
            this.mTempVisibleRect.offset(this.mTempGlobalRect[0] - this.mHost.getScrollX(), this.mTempGlobalRect[1] - this.mHost.getScrollY());
            boolean intersects = this.mTempScreenRect.intersect(this.mTempVisibleRect);
            if (intersects) {
                node.setBoundsInScreen(this.mTempScreenRect);
                if (isVisibleToUser(this.mTempScreenRect)) {
                    node.setVisibleToUser(true);
                }
            }
        }
        return node;
    }

    boolean performAction(int virtualViewId, int action, Bundle arguments) {
        switch (virtualViewId) {
            case -1:
                return performActionForHost(action, arguments);
            default:
                return performActionForChild(virtualViewId, action, arguments);
        }
    }

    private boolean performActionForHost(int action, Bundle arguments) {
        return ViewCompat.performAccessibilityAction(this.mHost, action, arguments);
    }

    private boolean performActionForChild(int virtualViewId, int action, Bundle arguments) {
        switch (action) {
            case 1:
                return requestKeyboardFocusForVirtualView(virtualViewId);
            case 2:
                return clearKeyboardFocusForVirtualView(virtualViewId);
            case 64:
                return requestAccessibilityFocus(virtualViewId);
            case 128:
                return clearAccessibilityFocus(virtualViewId);
            default:
                return onPerformActionForVirtualView(virtualViewId, action, arguments);
        }
    }

    private boolean isVisibleToUser(Rect localRect) {
        if (localRect == null || localRect.isEmpty() || this.mHost.getWindowVisibility() != 0) {
            return false;
        }
        ViewParent viewParent = this.mHost.getParent();
        while (viewParent instanceof View) {
            View view = (View) viewParent;
            if (view.getAlpha() <= 0.0f || view.getVisibility() != 0) {
                return false;
            }
            viewParent = view.getParent();
        }
        return viewParent != null;
    }

    private boolean requestAccessibilityFocus(int virtualViewId) {
        int i;
        if (this.mManager.isEnabled() && this.mManager.isTouchExplorationEnabled() && (i = this.mAccessibilityFocusedVirtualViewId) != virtualViewId) {
            if (i != Integer.MIN_VALUE) {
                clearAccessibilityFocus(i);
            }
            this.mAccessibilityFocusedVirtualViewId = virtualViewId;
            this.mHost.invalidate();
            sendEventForVirtualView(virtualViewId, 32768);
            return true;
        }
        return false;
    }

    private boolean clearAccessibilityFocus(int virtualViewId) {
        if (this.mAccessibilityFocusedVirtualViewId == virtualViewId) {
            this.mAccessibilityFocusedVirtualViewId = Integer.MIN_VALUE;
            this.mHost.invalidate();
            sendEventForVirtualView(virtualViewId, 65536);
            return true;
        }
        return false;
    }

    public final boolean requestKeyboardFocusForVirtualView(int virtualViewId) {
        int i;
        if ((this.mHost.isFocused() || this.mHost.requestFocus()) && (i = this.mKeyboardFocusedVirtualViewId) != virtualViewId) {
            if (i != Integer.MIN_VALUE) {
                clearKeyboardFocusForVirtualView(i);
            }
            if (virtualViewId == Integer.MIN_VALUE) {
                return false;
            }
            this.mKeyboardFocusedVirtualViewId = virtualViewId;
            onVirtualViewKeyboardFocusChanged(virtualViewId, true);
            sendEventForVirtualView(virtualViewId, 8);
            return true;
        }
        return false;
    }

    public final boolean clearKeyboardFocusForVirtualView(int virtualViewId) {
        if (this.mKeyboardFocusedVirtualViewId != virtualViewId) {
            return false;
        }
        this.mKeyboardFocusedVirtualViewId = Integer.MIN_VALUE;
        onVirtualViewKeyboardFocusChanged(virtualViewId, false);
        sendEventForVirtualView(virtualViewId, 8);
        return true;
    }

    protected void onPopulateEventForVirtualView(int virtualViewId, AccessibilityEvent event) {
    }

    protected void onPopulateEventForHost(AccessibilityEvent event) {
    }

    protected void onPopulateNodeForHost(AccessibilityNodeInfoCompat node) {
    }

    /* loaded from: classes.dex */
    private class MyNodeProvider extends AccessibilityNodeProviderCompat {
        MyNodeProvider() {
        }

        @Override // androidx.core.view.accessibility.AccessibilityNodeProviderCompat
        public AccessibilityNodeInfoCompat createAccessibilityNodeInfo(int virtualViewId) {
            AccessibilityNodeInfoCompat node = ExploreByTouchHelper.this.obtainAccessibilityNodeInfo(virtualViewId);
            return AccessibilityNodeInfoCompat.obtain(node);
        }

        @Override // androidx.core.view.accessibility.AccessibilityNodeProviderCompat
        public boolean performAction(int virtualViewId, int action, Bundle arguments) {
            return ExploreByTouchHelper.this.performAction(virtualViewId, action, arguments);
        }

        @Override // androidx.core.view.accessibility.AccessibilityNodeProviderCompat
        public AccessibilityNodeInfoCompat findFocus(int focusType) {
            int focusedId = focusType == 2 ? ExploreByTouchHelper.this.mAccessibilityFocusedVirtualViewId : ExploreByTouchHelper.this.mKeyboardFocusedVirtualViewId;
            if (focusedId == Integer.MIN_VALUE) {
                return null;
            }
            return createAccessibilityNodeInfo(focusedId);
        }
    }
}
