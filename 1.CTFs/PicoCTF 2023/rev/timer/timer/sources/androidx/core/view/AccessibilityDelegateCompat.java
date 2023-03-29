package androidx.core.view;

import android.os.Build;
import android.os.Bundle;
import android.text.style.ClickableSpan;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import androidx.core.R;
import androidx.core.view.accessibility.AccessibilityClickableSpanCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityNodeProviderCompat;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class AccessibilityDelegateCompat {
    private static final View.AccessibilityDelegate DEFAULT_DELEGATE = new View.AccessibilityDelegate();
    private final View.AccessibilityDelegate mBridge;
    private final View.AccessibilityDelegate mOriginalDelegate;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class AccessibilityDelegateAdapter extends View.AccessibilityDelegate {
        final AccessibilityDelegateCompat mCompat;

        AccessibilityDelegateAdapter(AccessibilityDelegateCompat compat) {
            this.mCompat = compat;
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            return this.mCompat.dispatchPopulateAccessibilityEvent(host, event);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            this.mCompat.onInitializeAccessibilityEvent(host, event);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
            AccessibilityNodeInfoCompat nodeInfoCompat = AccessibilityNodeInfoCompat.wrap(info);
            nodeInfoCompat.setScreenReaderFocusable(ViewCompat.isScreenReaderFocusable(host));
            nodeInfoCompat.setHeading(ViewCompat.isAccessibilityHeading(host));
            nodeInfoCompat.setPaneTitle(ViewCompat.getAccessibilityPaneTitle(host));
            nodeInfoCompat.setStateDescription(ViewCompat.getStateDescription(host));
            this.mCompat.onInitializeAccessibilityNodeInfo(host, nodeInfoCompat);
            nodeInfoCompat.addSpansToExtras(info.getText(), host);
            List<AccessibilityNodeInfoCompat.AccessibilityActionCompat> actions = AccessibilityDelegateCompat.getActionList(host);
            for (int i = 0; i < actions.size(); i++) {
                nodeInfoCompat.addAction(actions.get(i));
            }
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            this.mCompat.onPopulateAccessibilityEvent(host, event);
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
            return this.mCompat.onRequestSendAccessibilityEvent(host, child, event);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void sendAccessibilityEvent(View host, int eventType) {
            this.mCompat.sendAccessibilityEvent(host, eventType);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void sendAccessibilityEventUnchecked(View host, AccessibilityEvent event) {
            this.mCompat.sendAccessibilityEventUnchecked(host, event);
        }

        @Override // android.view.View.AccessibilityDelegate
        public AccessibilityNodeProvider getAccessibilityNodeProvider(View host) {
            AccessibilityNodeProviderCompat provider = this.mCompat.getAccessibilityNodeProvider(host);
            if (provider != null) {
                return (AccessibilityNodeProvider) provider.getProvider();
            }
            return null;
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean performAccessibilityAction(View host, int action, Bundle args) {
            return this.mCompat.performAccessibilityAction(host, action, args);
        }
    }

    public AccessibilityDelegateCompat() {
        this(DEFAULT_DELEGATE);
    }

    public AccessibilityDelegateCompat(View.AccessibilityDelegate originalDelegate) {
        this.mOriginalDelegate = originalDelegate;
        this.mBridge = new AccessibilityDelegateAdapter(this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public View.AccessibilityDelegate getBridge() {
        return this.mBridge;
    }

    public void sendAccessibilityEvent(View host, int eventType) {
        this.mOriginalDelegate.sendAccessibilityEvent(host, eventType);
    }

    public void sendAccessibilityEventUnchecked(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.sendAccessibilityEventUnchecked(host, event);
    }

    public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
        return this.mOriginalDelegate.dispatchPopulateAccessibilityEvent(host, event);
    }

    public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.onPopulateAccessibilityEvent(host, event);
    }

    public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.onInitializeAccessibilityEvent(host, event);
    }

    public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
        this.mOriginalDelegate.onInitializeAccessibilityNodeInfo(host, info.unwrap());
    }

    public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
        return this.mOriginalDelegate.onRequestSendAccessibilityEvent(host, child, event);
    }

    public AccessibilityNodeProviderCompat getAccessibilityNodeProvider(View host) {
        Object provider;
        if (Build.VERSION.SDK_INT >= 16 && (provider = this.mOriginalDelegate.getAccessibilityNodeProvider(host)) != null) {
            return new AccessibilityNodeProviderCompat(provider);
        }
        return null;
    }

    public boolean performAccessibilityAction(View host, int action, Bundle args) {
        boolean success = false;
        List<AccessibilityNodeInfoCompat.AccessibilityActionCompat> actions = getActionList(host);
        int i = 0;
        while (true) {
            if (i >= actions.size()) {
                break;
            }
            AccessibilityNodeInfoCompat.AccessibilityActionCompat actionCompat = actions.get(i);
            if (actionCompat.getId() != action) {
                i++;
            } else {
                success = actionCompat.perform(host, args);
                break;
            }
        }
        if (!success && Build.VERSION.SDK_INT >= 16) {
            success = this.mOriginalDelegate.performAccessibilityAction(host, action, args);
        }
        if (!success && action == R.id.accessibility_action_clickable_span) {
            boolean success2 = performClickableSpanAction(args.getInt(AccessibilityClickableSpanCompat.SPAN_ID, -1), host);
            return success2;
        }
        return success;
    }

    private boolean performClickableSpanAction(int clickableSpanId, View host) {
        WeakReference<ClickableSpan> reference;
        SparseArray<WeakReference<ClickableSpan>> spans = (SparseArray) host.getTag(R.id.tag_accessibility_clickable_spans);
        if (spans != null && (reference = spans.get(clickableSpanId)) != null) {
            ClickableSpan span = reference.get();
            if (isSpanStillValid(span, host)) {
                span.onClick(host);
                return true;
            }
            return false;
        }
        return false;
    }

    private boolean isSpanStillValid(ClickableSpan span, View view) {
        if (span != null) {
            AccessibilityNodeInfo info = view.createAccessibilityNodeInfo();
            ClickableSpan[] spans = AccessibilityNodeInfoCompat.getClickableSpans(info.getText());
            for (int i = 0; spans != null && i < spans.length; i++) {
                if (span.equals(spans[i])) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    static List<AccessibilityNodeInfoCompat.AccessibilityActionCompat> getActionList(View view) {
        List<AccessibilityNodeInfoCompat.AccessibilityActionCompat> actions = (List) view.getTag(R.id.tag_accessibility_actions);
        return actions == null ? Collections.emptyList() : actions;
    }
}
