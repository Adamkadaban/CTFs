package androidx.core.location;

import android.location.LocationRequest;
import android.os.Build;
import androidx.core.util.Preconditions;
import androidx.core.util.TimeUtils;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public final class LocationRequestCompat {
    private static final long IMPLICIT_MIN_UPDATE_INTERVAL = -1;
    public static final long PASSIVE_INTERVAL = Long.MAX_VALUE;
    public static final int QUALITY_BALANCED_POWER_ACCURACY = 102;
    public static final int QUALITY_HIGH_ACCURACY = 100;
    public static final int QUALITY_LOW_POWER = 104;
    private static Method sCreateFromDeprecatedProviderMethod;
    private static Method sSetExpireInMethod;
    private static Method sSetFastestIntervalMethod;
    private static Method sSetNumUpdatesMethod;
    private static Method sSetQualityMethod;
    final long mDurationMillis;
    final long mIntervalMillis;
    final long mMaxUpdateDelayMillis;
    final int mMaxUpdates;
    final float mMinUpdateDistanceMeters;
    final long mMinUpdateIntervalMillis;
    final int mQuality;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface Quality {
    }

    LocationRequestCompat(long intervalMillis, int quality, long durationMillis, int maxUpdates, long minUpdateIntervalMillis, float minUpdateDistanceMeters, long maxUpdateDelayMillis) {
        this.mIntervalMillis = intervalMillis;
        this.mQuality = quality;
        this.mMinUpdateIntervalMillis = minUpdateIntervalMillis;
        this.mDurationMillis = durationMillis;
        this.mMaxUpdates = maxUpdates;
        this.mMinUpdateDistanceMeters = minUpdateDistanceMeters;
        this.mMaxUpdateDelayMillis = maxUpdateDelayMillis;
    }

    public int getQuality() {
        return this.mQuality;
    }

    public long getIntervalMillis() {
        return this.mIntervalMillis;
    }

    public long getMinUpdateIntervalMillis() {
        long j = this.mMinUpdateIntervalMillis;
        if (j == -1) {
            return this.mIntervalMillis;
        }
        return j;
    }

    public long getDurationMillis() {
        return this.mDurationMillis;
    }

    public int getMaxUpdates() {
        return this.mMaxUpdates;
    }

    public float getMinUpdateDistanceMeters() {
        return this.mMinUpdateDistanceMeters;
    }

    public long getMaxUpdateDelayMillis() {
        return this.mMaxUpdateDelayMillis;
    }

    public LocationRequest toLocationRequest() {
        return new LocationRequest.Builder(this.mIntervalMillis).setQuality(this.mQuality).setMinUpdateIntervalMillis(this.mMinUpdateIntervalMillis).setDurationMillis(this.mDurationMillis).setMaxUpdates(this.mMaxUpdates).setMinUpdateDistanceMeters(this.mMinUpdateDistanceMeters).setMaxUpdateDelayMillis(this.mMaxUpdateDelayMillis).build();
    }

    public LocationRequest toLocationRequest(String provider) {
        if (Build.VERSION.SDK_INT >= 31) {
            return toLocationRequest();
        }
        try {
            if (sCreateFromDeprecatedProviderMethod == null) {
                Method declaredMethod = LocationRequest.class.getDeclaredMethod("createFromDeprecatedProvider", String.class, Long.TYPE, Float.TYPE, Boolean.TYPE);
                sCreateFromDeprecatedProviderMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            }
            LocationRequest request = (LocationRequest) sCreateFromDeprecatedProviderMethod.invoke(null, provider, Long.valueOf(this.mIntervalMillis), Float.valueOf(this.mMinUpdateDistanceMeters), false);
            if (request == null) {
                return null;
            }
            if (sSetQualityMethod == null) {
                Method declaredMethod2 = LocationRequest.class.getDeclaredMethod("setQuality", Integer.TYPE);
                sSetQualityMethod = declaredMethod2;
                declaredMethod2.setAccessible(true);
            }
            sSetQualityMethod.invoke(request, Integer.valueOf(this.mQuality));
            if (getMinUpdateIntervalMillis() != this.mIntervalMillis) {
                if (sSetFastestIntervalMethod == null) {
                    Method declaredMethod3 = LocationRequest.class.getDeclaredMethod("setFastestInterval", Long.TYPE);
                    sSetFastestIntervalMethod = declaredMethod3;
                    declaredMethod3.setAccessible(true);
                }
                sSetFastestIntervalMethod.invoke(request, Long.valueOf(this.mMinUpdateIntervalMillis));
            }
            if (this.mMaxUpdates < Integer.MAX_VALUE) {
                if (sSetNumUpdatesMethod == null) {
                    Method declaredMethod4 = LocationRequest.class.getDeclaredMethod("setNumUpdates", Integer.TYPE);
                    sSetNumUpdatesMethod = declaredMethod4;
                    declaredMethod4.setAccessible(true);
                }
                sSetNumUpdatesMethod.invoke(request, Integer.valueOf(this.mMaxUpdates));
            }
            if (this.mDurationMillis < Long.MAX_VALUE) {
                if (sSetExpireInMethod == null) {
                    Method declaredMethod5 = LocationRequest.class.getDeclaredMethod("setExpireIn", Long.TYPE);
                    sSetExpireInMethod = declaredMethod5;
                    declaredMethod5.setAccessible(true);
                }
                sSetExpireInMethod.invoke(request, Long.valueOf(this.mDurationMillis));
            }
            return request;
        } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
            return null;
        }
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof LocationRequestCompat) {
            LocationRequestCompat that = (LocationRequestCompat) o;
            return this.mQuality == that.mQuality && this.mIntervalMillis == that.mIntervalMillis && this.mMinUpdateIntervalMillis == that.mMinUpdateIntervalMillis && this.mDurationMillis == that.mDurationMillis && this.mMaxUpdates == that.mMaxUpdates && Float.compare(that.mMinUpdateDistanceMeters, this.mMinUpdateDistanceMeters) == 0 && this.mMaxUpdateDelayMillis == that.mMaxUpdateDelayMillis;
        }
        return false;
    }

    public int hashCode() {
        int result = this.mQuality;
        long j = this.mIntervalMillis;
        int result2 = (result * 31) + ((int) (j ^ (j >>> 32)));
        long j2 = this.mMinUpdateIntervalMillis;
        return (result2 * 31) + ((int) (j2 ^ (j2 >>> 32)));
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Request[");
        if (this.mIntervalMillis != Long.MAX_VALUE) {
            s.append("@");
            TimeUtils.formatDuration(this.mIntervalMillis, s);
            switch (this.mQuality) {
                case 100:
                    s.append(" HIGH_ACCURACY");
                    break;
                case 102:
                    s.append(" BALANCED");
                    break;
                case 104:
                    s.append(" LOW_POWER");
                    break;
            }
        } else {
            s.append("PASSIVE");
        }
        if (this.mDurationMillis != Long.MAX_VALUE) {
            s.append(", duration=");
            TimeUtils.formatDuration(this.mDurationMillis, s);
        }
        if (this.mMaxUpdates != Integer.MAX_VALUE) {
            s.append(", maxUpdates=");
            s.append(this.mMaxUpdates);
        }
        long j = this.mMinUpdateIntervalMillis;
        if (j != -1 && j < this.mIntervalMillis) {
            s.append(", minUpdateInterval=");
            TimeUtils.formatDuration(this.mMinUpdateIntervalMillis, s);
        }
        if (this.mMinUpdateDistanceMeters > 0.0d) {
            s.append(", minUpdateDistance=");
            s.append(this.mMinUpdateDistanceMeters);
        }
        if (this.mMaxUpdateDelayMillis / 2 > this.mIntervalMillis) {
            s.append(", maxUpdateDelay=");
            TimeUtils.formatDuration(this.mMaxUpdateDelayMillis, s);
        }
        s.append(']');
        return s.toString();
    }

    /* loaded from: classes.dex */
    public static final class Builder {
        private long mDurationMillis;
        private long mIntervalMillis;
        private long mMaxUpdateDelayMillis;
        private int mMaxUpdates;
        private float mMinUpdateDistanceMeters;
        private long mMinUpdateIntervalMillis;
        private int mQuality;

        public Builder(long intervalMillis) {
            setIntervalMillis(intervalMillis);
            this.mQuality = 102;
            this.mDurationMillis = Long.MAX_VALUE;
            this.mMaxUpdates = Integer.MAX_VALUE;
            this.mMinUpdateIntervalMillis = -1L;
            this.mMinUpdateDistanceMeters = 0.0f;
            this.mMaxUpdateDelayMillis = 0L;
        }

        public Builder(LocationRequestCompat locationRequest) {
            this.mIntervalMillis = locationRequest.mIntervalMillis;
            this.mQuality = locationRequest.mQuality;
            this.mDurationMillis = locationRequest.mDurationMillis;
            this.mMaxUpdates = locationRequest.mMaxUpdates;
            this.mMinUpdateIntervalMillis = locationRequest.mMinUpdateIntervalMillis;
            this.mMinUpdateDistanceMeters = locationRequest.mMinUpdateDistanceMeters;
            this.mMaxUpdateDelayMillis = locationRequest.mMaxUpdateDelayMillis;
        }

        public Builder setIntervalMillis(long intervalMillis) {
            this.mIntervalMillis = Preconditions.checkArgumentInRange(intervalMillis, 0L, Long.MAX_VALUE, "intervalMillis");
            return this;
        }

        public Builder setQuality(int quality) {
            Preconditions.checkArgument(quality == 104 || quality == 102 || quality == 100, "quality must be a defined QUALITY constant, not %d", Integer.valueOf(quality));
            this.mQuality = quality;
            return this;
        }

        public Builder setDurationMillis(long durationMillis) {
            this.mDurationMillis = Preconditions.checkArgumentInRange(durationMillis, 1L, Long.MAX_VALUE, "durationMillis");
            return this;
        }

        public Builder setMaxUpdates(int maxUpdates) {
            this.mMaxUpdates = Preconditions.checkArgumentInRange(maxUpdates, 1, Integer.MAX_VALUE, "maxUpdates");
            return this;
        }

        public Builder setMinUpdateIntervalMillis(long minUpdateIntervalMillis) {
            this.mMinUpdateIntervalMillis = Preconditions.checkArgumentInRange(minUpdateIntervalMillis, 0L, Long.MAX_VALUE, "minUpdateIntervalMillis");
            return this;
        }

        public Builder clearMinUpdateIntervalMillis() {
            this.mMinUpdateIntervalMillis = -1L;
            return this;
        }

        public Builder setMinUpdateDistanceMeters(float minUpdateDistanceMeters) {
            this.mMinUpdateDistanceMeters = minUpdateDistanceMeters;
            this.mMinUpdateDistanceMeters = Preconditions.checkArgumentInRange(minUpdateDistanceMeters, 0.0f, Float.MAX_VALUE, "minUpdateDistanceMeters");
            return this;
        }

        public Builder setMaxUpdateDelayMillis(long maxUpdateDelayMillis) {
            this.mMaxUpdateDelayMillis = maxUpdateDelayMillis;
            this.mMaxUpdateDelayMillis = Preconditions.checkArgumentInRange(maxUpdateDelayMillis, 0L, Long.MAX_VALUE, "maxUpdateDelayMillis");
            return this;
        }

        public LocationRequestCompat build() {
            Preconditions.checkState((this.mIntervalMillis == Long.MAX_VALUE && this.mMinUpdateIntervalMillis == -1) ? false : true, "passive location requests must have an explicit minimum update interval");
            long j = this.mIntervalMillis;
            return new LocationRequestCompat(j, this.mQuality, this.mDurationMillis, this.mMaxUpdates, Math.min(this.mMinUpdateIntervalMillis, j), this.mMinUpdateDistanceMeters, this.mMaxUpdateDelayMillis);
        }
    }
}
