package androidx.core.content;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import androidx.concurrent.futures.ResolvableFuture;
import androidx.core.app.unusedapprestrictions.IUnusedAppRestrictionsBackportCallback;
import androidx.core.app.unusedapprestrictions.IUnusedAppRestrictionsBackportService;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class UnusedAppRestrictionsBackportServiceConnection implements ServiceConnection {
    private final Context mContext;
    ResolvableFuture<Integer> mResultFuture;
    IUnusedAppRestrictionsBackportService mUnusedAppRestrictionsService = null;
    private boolean mHasBoundService = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UnusedAppRestrictionsBackportServiceConnection(Context context) {
        this.mContext = context;
    }

    @Override // android.content.ServiceConnection
    public void onServiceConnected(ComponentName name, IBinder service) {
        IUnusedAppRestrictionsBackportService asInterface = IUnusedAppRestrictionsBackportService.Stub.asInterface(service);
        this.mUnusedAppRestrictionsService = asInterface;
        try {
            asInterface.isPermissionRevocationEnabledForApp(getBackportCallback());
        } catch (RemoteException e) {
            this.mResultFuture.set(0);
        }
    }

    @Override // android.content.ServiceConnection
    public void onServiceDisconnected(ComponentName name) {
        this.mUnusedAppRestrictionsService = null;
    }

    public void connectAndFetchResult(ResolvableFuture<Integer> resultFuture) {
        if (this.mHasBoundService) {
            throw new IllegalStateException("Each UnusedAppRestrictionsBackportServiceConnection can only be bound once.");
        }
        this.mHasBoundService = true;
        this.mResultFuture = resultFuture;
        Intent intent = new Intent(UnusedAppRestrictionsBackportService.ACTION_UNUSED_APP_RESTRICTIONS_BACKPORT_CONNECTION).setPackage(PackageManagerCompat.getPermissionRevocationVerifierApp(this.mContext.getPackageManager()));
        this.mContext.bindService(intent, this, 1);
    }

    public void disconnectFromService() {
        if (!this.mHasBoundService) {
            throw new IllegalStateException("bindService must be called before unbind");
        }
        this.mHasBoundService = false;
        this.mContext.unbindService(this);
    }

    private IUnusedAppRestrictionsBackportCallback getBackportCallback() {
        return new IUnusedAppRestrictionsBackportCallback.Stub() { // from class: androidx.core.content.UnusedAppRestrictionsBackportServiceConnection.1
            @Override // androidx.core.app.unusedapprestrictions.IUnusedAppRestrictionsBackportCallback
            public void onIsPermissionRevocationEnabledForAppResult(boolean success, boolean isEnabled) throws RemoteException {
                if (success) {
                    if (isEnabled) {
                        UnusedAppRestrictionsBackportServiceConnection.this.mResultFuture.set(3);
                        return;
                    } else {
                        UnusedAppRestrictionsBackportServiceConnection.this.mResultFuture.set(2);
                        return;
                    }
                }
                UnusedAppRestrictionsBackportServiceConnection.this.mResultFuture.set(0);
                Log.e(PackageManagerCompat.LOG_TAG, "Unable to retrieve the permission revocation setting from the backport");
            }
        };
    }
}
