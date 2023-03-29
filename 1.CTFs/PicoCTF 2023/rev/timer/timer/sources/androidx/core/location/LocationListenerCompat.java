package androidx.core.location;

import android.location.LocationListener;
import android.os.Bundle;
/* loaded from: classes.dex */
public interface LocationListenerCompat extends LocationListener {
    @Override // android.location.LocationListener
    void onProviderDisabled(String str);

    @Override // android.location.LocationListener
    void onProviderEnabled(String str);

    @Override // android.location.LocationListener
    void onStatusChanged(String str, int i, Bundle bundle);

    /* renamed from: androidx.core.location.LocationListenerCompat$-CC  reason: invalid class name */
    /* loaded from: classes.dex */
    public final /* synthetic */ class CC {
        public static void $default$onStatusChanged(LocationListenerCompat _this, String provider, int status, Bundle extras) {
        }

        public static void $default$onProviderEnabled(LocationListenerCompat _this, String provider) {
        }

        public static void $default$onProviderDisabled(LocationListenerCompat _this, String provider) {
        }
    }
}
