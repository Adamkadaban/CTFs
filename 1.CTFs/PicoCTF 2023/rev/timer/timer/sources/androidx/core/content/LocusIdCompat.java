package androidx.core.content;

import android.content.LocusId;
import android.os.Build;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public final class LocusIdCompat {
    private final String mId;
    private final LocusId mWrapped;

    public LocusIdCompat(String id) {
        this.mId = (String) Preconditions.checkStringNotEmpty(id, "id cannot be empty");
        if (Build.VERSION.SDK_INT >= 29) {
            this.mWrapped = Api29Impl.create(id);
        } else {
            this.mWrapped = null;
        }
    }

    public String getId() {
        return this.mId;
    }

    public int hashCode() {
        int i = 1 * 31;
        String str = this.mId;
        int result = i + (str == null ? 0 : str.hashCode());
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LocusIdCompat other = (LocusIdCompat) obj;
        String str = this.mId;
        if (str == null) {
            return other.mId == null;
        }
        return str.equals(other.mId);
    }

    public String toString() {
        return "LocusIdCompat[" + getSanitizedId() + "]";
    }

    public LocusId toLocusId() {
        return this.mWrapped;
    }

    public static LocusIdCompat toLocusIdCompat(LocusId locusId) {
        Preconditions.checkNotNull(locusId, "locusId cannot be null");
        return new LocusIdCompat((String) Preconditions.checkStringNotEmpty(Api29Impl.getId(locusId), "id cannot be empty"));
    }

    private String getSanitizedId() {
        int size = this.mId.length();
        return size + "_chars";
    }

    /* loaded from: classes.dex */
    private static class Api29Impl {
        private Api29Impl() {
        }

        static LocusId create(String id) {
            return new LocusId(id);
        }

        static String getId(LocusId obj) {
            return obj.getId();
        }
    }
}
