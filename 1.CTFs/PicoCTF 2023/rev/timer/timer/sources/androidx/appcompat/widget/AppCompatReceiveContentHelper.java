package androidx.appcompat.widget;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Build;
import android.text.Selection;
import android.text.Spannable;
import android.util.Log;
import android.view.DragEvent;
import android.view.View;
import android.widget.TextView;
import androidx.core.view.ContentInfoCompat;
import androidx.core.view.ViewCompat;
/* loaded from: classes.dex */
final class AppCompatReceiveContentHelper {
    private static final String LOG_TAG = "ReceiveContent";

    private AppCompatReceiveContentHelper() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean maybeHandleMenuActionViaPerformReceiveContent(TextView view, int actionId) {
        if (Build.VERSION.SDK_INT >= 31 || ViewCompat.getOnReceiveContentMimeTypes(view) == null || !(actionId == 16908322 || actionId == 16908337)) {
            return false;
        }
        ClipboardManager cm = (ClipboardManager) view.getContext().getSystemService("clipboard");
        ClipData clip = cm == null ? null : cm.getPrimaryClip();
        if (clip != null && clip.getItemCount() > 0) {
            ContentInfoCompat payload = new ContentInfoCompat.Builder(clip, 1).setFlags(actionId != 16908322 ? 1 : 0).build();
            ViewCompat.performReceiveContent(view, payload);
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean maybeHandleDragEventViaPerformReceiveContent(View view, DragEvent event) {
        if (Build.VERSION.SDK_INT >= 31 || Build.VERSION.SDK_INT < 24 || event.getLocalState() != null || ViewCompat.getOnReceiveContentMimeTypes(view) == null) {
            return false;
        }
        Activity activity = tryGetActivity(view);
        if (activity == null) {
            Log.i(LOG_TAG, "Can't handle drop: no activity: view=" + view);
            return false;
        } else if (event.getAction() == 1) {
            return !(view instanceof TextView);
        } else {
            if (event.getAction() == 3) {
                if (view instanceof TextView) {
                    return OnDropApi24Impl.onDropForTextView(event, (TextView) view, activity);
                }
                return OnDropApi24Impl.onDropForView(event, view, activity);
            }
            return false;
        }
    }

    /* loaded from: classes.dex */
    private static final class OnDropApi24Impl {
        private OnDropApi24Impl() {
        }

        static boolean onDropForTextView(DragEvent event, TextView view, Activity activity) {
            activity.requestDragAndDropPermissions(event);
            int offset = view.getOffsetForPosition(event.getX(), event.getY());
            view.beginBatchEdit();
            try {
                Selection.setSelection((Spannable) view.getText(), offset);
                ContentInfoCompat payload = new ContentInfoCompat.Builder(event.getClipData(), 3).build();
                ViewCompat.performReceiveContent(view, payload);
                view.endBatchEdit();
                return true;
            } catch (Throwable th) {
                view.endBatchEdit();
                throw th;
            }
        }

        static boolean onDropForView(DragEvent event, View view, Activity activity) {
            activity.requestDragAndDropPermissions(event);
            ContentInfoCompat payload = new ContentInfoCompat.Builder(event.getClipData(), 3).build();
            ViewCompat.performReceiveContent(view, payload);
            return true;
        }
    }

    static Activity tryGetActivity(View view) {
        for (Context context = view.getContext(); context instanceof ContextWrapper; context = ((ContextWrapper) context).getBaseContext()) {
            if (context instanceof Activity) {
                return (Activity) context;
            }
        }
        return null;
    }
}
