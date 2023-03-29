package androidx.core.database;

import android.database.Cursor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Cursor.kt */
@Metadata(d1 = {"\u00008\n\u0000\n\u0002\u0010\u0012\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0006\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\n\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\u001a\u0017\u0010\u0000\u001a\u0004\u0018\u00010\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b\u001a\u001c\u0010\u0005\u001a\u0004\u0018\u00010\u0006*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¢\u0006\u0002\u0010\u0007\u001a\u001c\u0010\b\u001a\u0004\u0018\u00010\t*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¢\u0006\u0002\u0010\n\u001a\u001c\u0010\u000b\u001a\u0004\u0018\u00010\u0004*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¢\u0006\u0002\u0010\f\u001a\u001c\u0010\r\u001a\u0004\u0018\u00010\u000e*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¢\u0006\u0002\u0010\u000f\u001a\u001c\u0010\u0010\u001a\u0004\u0018\u00010\u0011*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¢\u0006\u0002\u0010\u0012\u001a\u0017\u0010\u0013\u001a\u0004\u0018\u00010\u0014*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b¨\u0006\u0015"}, d2 = {"getBlobOrNull", "", "Landroid/database/Cursor;", "index", "", "getDoubleOrNull", "", "(Landroid/database/Cursor;I)Ljava/lang/Double;", "getFloatOrNull", "", "(Landroid/database/Cursor;I)Ljava/lang/Float;", "getIntOrNull", "(Landroid/database/Cursor;I)Ljava/lang/Integer;", "getLongOrNull", "", "(Landroid/database/Cursor;I)Ljava/lang/Long;", "getShortOrNull", "", "(Landroid/database/Cursor;I)Ljava/lang/Short;", "getStringOrNull", "", "core-ktx_release"}, k = 2, mv = {1, 5, 1}, xi = 48)
/* loaded from: classes.dex */
public final class CursorKt {
    public static final byte[] getBlobOrNull(Cursor $this$getBlobOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getBlobOrNull, "<this>");
        if ($this$getBlobOrNull.isNull(index)) {
            return null;
        }
        return $this$getBlobOrNull.getBlob(index);
    }

    public static final Double getDoubleOrNull(Cursor $this$getDoubleOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getDoubleOrNull, "<this>");
        if ($this$getDoubleOrNull.isNull(index)) {
            return null;
        }
        return Double.valueOf($this$getDoubleOrNull.getDouble(index));
    }

    public static final Float getFloatOrNull(Cursor $this$getFloatOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getFloatOrNull, "<this>");
        if ($this$getFloatOrNull.isNull(index)) {
            return null;
        }
        return Float.valueOf($this$getFloatOrNull.getFloat(index));
    }

    public static final Integer getIntOrNull(Cursor $this$getIntOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getIntOrNull, "<this>");
        if ($this$getIntOrNull.isNull(index)) {
            return null;
        }
        return Integer.valueOf($this$getIntOrNull.getInt(index));
    }

    public static final Long getLongOrNull(Cursor $this$getLongOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getLongOrNull, "<this>");
        if ($this$getLongOrNull.isNull(index)) {
            return null;
        }
        return Long.valueOf($this$getLongOrNull.getLong(index));
    }

    public static final Short getShortOrNull(Cursor $this$getShortOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getShortOrNull, "<this>");
        if ($this$getShortOrNull.isNull(index)) {
            return null;
        }
        return Short.valueOf($this$getShortOrNull.getShort(index));
    }

    public static final String getStringOrNull(Cursor $this$getStringOrNull, int index) {
        Intrinsics.checkNotNullParameter($this$getStringOrNull, "<this>");
        if ($this$getStringOrNull.isNull(index)) {
            return null;
        }
        return $this$getStringOrNull.getString(index);
    }
}
