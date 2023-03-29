package androidx.core.location;

import android.location.GpsSatellite;
import android.location.GpsStatus;
import android.os.Build;
import androidx.core.util.Preconditions;
import java.util.Iterator;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class GpsStatusWrapper extends GnssStatusCompat {
    private static final int BEIDOU_PRN_COUNT = 35;
    private static final int BEIDOU_PRN_OFFSET = 200;
    private static final int GLONASS_PRN_COUNT = 24;
    private static final int GLONASS_PRN_OFFSET = 64;
    private static final int GPS_PRN_COUNT = 32;
    private static final int GPS_PRN_OFFSET = 0;
    private static final int QZSS_SVID_MAX = 200;
    private static final int QZSS_SVID_MIN = 193;
    private static final int SBAS_PRN_MAX = 64;
    private static final int SBAS_PRN_MIN = 33;
    private static final int SBAS_PRN_OFFSET = -87;
    private Iterator<GpsSatellite> mCachedIterator;
    private int mCachedIteratorPosition;
    private GpsSatellite mCachedSatellite;
    private int mCachedSatelliteCount;
    private final GpsStatus mWrapped;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GpsStatusWrapper(GpsStatus gpsStatus) {
        GpsStatus gpsStatus2 = (GpsStatus) Preconditions.checkNotNull(gpsStatus);
        this.mWrapped = gpsStatus2;
        this.mCachedSatelliteCount = -1;
        this.mCachedIterator = gpsStatus2.getSatellites().iterator();
        this.mCachedIteratorPosition = -1;
        this.mCachedSatellite = null;
    }

    @Override // androidx.core.location.GnssStatusCompat
    public int getSatelliteCount() {
        int i;
        synchronized (this.mWrapped) {
            if (this.mCachedSatelliteCount == -1) {
                for (GpsSatellite gpsSatellite : this.mWrapped.getSatellites()) {
                    this.mCachedSatelliteCount++;
                }
                this.mCachedSatelliteCount++;
            }
            i = this.mCachedSatelliteCount;
        }
        return i;
    }

    @Override // androidx.core.location.GnssStatusCompat
    public int getConstellationType(int satelliteIndex) {
        if (Build.VERSION.SDK_INT < 24) {
            return 1;
        }
        return getConstellationFromPrn(getSatellite(satelliteIndex).getPrn());
    }

    @Override // androidx.core.location.GnssStatusCompat
    public int getSvid(int satelliteIndex) {
        if (Build.VERSION.SDK_INT < 24) {
            return getSatellite(satelliteIndex).getPrn();
        }
        return getSvidFromPrn(getSatellite(satelliteIndex).getPrn());
    }

    @Override // androidx.core.location.GnssStatusCompat
    public float getCn0DbHz(int satelliteIndex) {
        return getSatellite(satelliteIndex).getSnr();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public float getElevationDegrees(int satelliteIndex) {
        return getSatellite(satelliteIndex).getElevation();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public float getAzimuthDegrees(int satelliteIndex) {
        return getSatellite(satelliteIndex).getAzimuth();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public boolean hasEphemerisData(int satelliteIndex) {
        return getSatellite(satelliteIndex).hasEphemeris();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public boolean hasAlmanacData(int satelliteIndex) {
        return getSatellite(satelliteIndex).hasAlmanac();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public boolean usedInFix(int satelliteIndex) {
        return getSatellite(satelliteIndex).usedInFix();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public boolean hasCarrierFrequencyHz(int satelliteIndex) {
        return false;
    }

    @Override // androidx.core.location.GnssStatusCompat
    public float getCarrierFrequencyHz(int satelliteIndex) {
        throw new UnsupportedOperationException();
    }

    @Override // androidx.core.location.GnssStatusCompat
    public boolean hasBasebandCn0DbHz(int satelliteIndex) {
        return false;
    }

    @Override // androidx.core.location.GnssStatusCompat
    public float getBasebandCn0DbHz(int satelliteIndex) {
        throw new UnsupportedOperationException();
    }

    private GpsSatellite getSatellite(int satelliteIndex) {
        GpsSatellite satellite;
        synchronized (this.mWrapped) {
            if (satelliteIndex < this.mCachedIteratorPosition) {
                this.mCachedIterator = this.mWrapped.getSatellites().iterator();
                this.mCachedIteratorPosition = -1;
            }
            while (true) {
                int i = this.mCachedIteratorPosition;
                if (i >= satelliteIndex) {
                    break;
                }
                this.mCachedIteratorPosition = i + 1;
                if (!this.mCachedIterator.hasNext()) {
                    this.mCachedSatellite = null;
                    break;
                }
                this.mCachedSatellite = this.mCachedIterator.next();
            }
            satellite = this.mCachedSatellite;
        }
        return (GpsSatellite) Preconditions.checkNotNull(satellite);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof GpsStatusWrapper)) {
            return false;
        }
        GpsStatusWrapper that = (GpsStatusWrapper) o;
        return this.mWrapped.equals(that.mWrapped);
    }

    public int hashCode() {
        return this.mWrapped.hashCode();
    }

    private static int getConstellationFromPrn(int prn) {
        if (prn > 0 && prn <= 32) {
            return 1;
        }
        if (prn >= 33 && prn <= 64) {
            return 2;
        }
        if (prn > 64 && prn <= 88) {
            return 3;
        }
        if (prn > 200 && prn <= 235) {
            return 5;
        }
        if (prn >= QZSS_SVID_MIN && prn <= 200) {
            return 4;
        }
        return 0;
    }

    private static int getSvidFromPrn(int prn) {
        switch (getConstellationFromPrn(prn)) {
            case 2:
                return prn + 87;
            case 3:
                return prn - 64;
            case 4:
            default:
                return prn;
            case 5:
                return prn - 200;
        }
    }
}
