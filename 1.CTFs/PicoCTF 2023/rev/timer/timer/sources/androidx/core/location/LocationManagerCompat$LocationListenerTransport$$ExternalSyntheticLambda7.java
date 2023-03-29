package androidx.core.location;

import androidx.core.location.LocationManagerCompat;
import java.lang.ref.WeakReference;
import java.util.function.Predicate;
/* compiled from: D8$$SyntheticClass */
/* loaded from: classes.dex */
public final /* synthetic */ class LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda7 implements Predicate {
    public static final /* synthetic */ LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda7 INSTANCE = new LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda7();

    private /* synthetic */ LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda7() {
    }

    @Override // java.util.function.Predicate
    public final boolean test(Object obj) {
        return LocationManagerCompat.LocationListenerTransport.lambda$unregister$1((WeakReference) obj);
    }
}
