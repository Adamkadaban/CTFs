package androidx.core.content;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.OperationCanceledException;
import androidx.core.os.CancellationSignal;
/* loaded from: classes.dex */
public final class ContentResolverCompat {
    private ContentResolverCompat() {
    }

    public static Cursor query(ContentResolver resolver, Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder, CancellationSignal cancellationSignal) {
        Object cancellationSignalObject;
        if (Build.VERSION.SDK_INT >= 16) {
            if (cancellationSignal != null) {
                try {
                    cancellationSignalObject = cancellationSignal.getCancellationSignalObject();
                } catch (Exception e) {
                    if (e instanceof OperationCanceledException) {
                        throw new androidx.core.os.OperationCanceledException();
                    }
                    throw e;
                }
            } else {
                cancellationSignalObject = null;
            }
            android.os.CancellationSignal cancellationSignalObj = (android.os.CancellationSignal) cancellationSignalObject;
            return resolver.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignalObj);
        }
        if (cancellationSignal != null) {
            cancellationSignal.throwIfCanceled();
        }
        return resolver.query(uri, projection, selection, selectionArgs, sortOrder);
    }
}
