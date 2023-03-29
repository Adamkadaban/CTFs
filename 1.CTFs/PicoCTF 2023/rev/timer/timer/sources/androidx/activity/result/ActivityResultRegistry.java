package androidx.activity.result;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.activity.result.contract.ActivityResultContract;
import androidx.core.app.ActivityOptionsCompat;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
/* loaded from: classes.dex */
public abstract class ActivityResultRegistry {
    private static final int INITIAL_REQUEST_CODE_VALUE = 65536;
    private static final String KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS = "KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS";
    private static final String KEY_COMPONENT_ACTIVITY_PENDING_RESULTS = "KEY_COMPONENT_ACTIVITY_PENDING_RESULT";
    private static final String KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT = "KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT";
    private static final String KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS = "KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS";
    private static final String KEY_COMPONENT_ACTIVITY_REGISTERED_RCS = "KEY_COMPONENT_ACTIVITY_REGISTERED_RCS";
    private static final String LOG_TAG = "ActivityResultRegistry";
    private Random mRandom = new Random();
    private final Map<Integer, String> mRcToKey = new HashMap();
    final Map<String, Integer> mKeyToRc = new HashMap();
    private final Map<String, LifecycleContainer> mKeyToLifecycleContainers = new HashMap();
    ArrayList<String> mLaunchedKeys = new ArrayList<>();
    final transient Map<String, CallbackAndContract<?>> mKeyToCallback = new HashMap();
    final Map<String, Object> mParsedPendingResults = new HashMap();
    final Bundle mPendingResults = new Bundle();

    public abstract <I, O> void onLaunch(int i, ActivityResultContract<I, O> activityResultContract, I i2, ActivityOptionsCompat activityOptionsCompat);

    public final <I, O> ActivityResultLauncher<I> register(final String key, LifecycleOwner lifecycleOwner, final ActivityResultContract<I, O> contract, final ActivityResultCallback<O> callback) {
        Lifecycle lifecycle = lifecycleOwner.getLifecycle();
        if (lifecycle.getCurrentState().isAtLeast(Lifecycle.State.STARTED)) {
            throw new IllegalStateException("LifecycleOwner " + lifecycleOwner + " is attempting to register while current state is " + lifecycle.getCurrentState() + ". LifecycleOwners must call register before they are STARTED.");
        }
        final int requestCode = registerKey(key);
        LifecycleContainer lifecycleContainer = this.mKeyToLifecycleContainers.get(key);
        if (lifecycleContainer == null) {
            lifecycleContainer = new LifecycleContainer(lifecycle);
        }
        LifecycleEventObserver observer = new LifecycleEventObserver() { // from class: androidx.activity.result.ActivityResultRegistry.1
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner lifecycleOwner2, Lifecycle.Event event) {
                if (!Lifecycle.Event.ON_START.equals(event)) {
                    if (Lifecycle.Event.ON_STOP.equals(event)) {
                        ActivityResultRegistry.this.mKeyToCallback.remove(key);
                        return;
                    } else if (Lifecycle.Event.ON_DESTROY.equals(event)) {
                        ActivityResultRegistry.this.unregister(key);
                        return;
                    } else {
                        return;
                    }
                }
                ActivityResultRegistry.this.mKeyToCallback.put(key, new CallbackAndContract<>(callback, contract));
                if (ActivityResultRegistry.this.mParsedPendingResults.containsKey(key)) {
                    Object obj = ActivityResultRegistry.this.mParsedPendingResults.get(key);
                    ActivityResultRegistry.this.mParsedPendingResults.remove(key);
                    callback.onActivityResult(obj);
                }
                ActivityResult pendingResult = (ActivityResult) ActivityResultRegistry.this.mPendingResults.getParcelable(key);
                if (pendingResult != null) {
                    ActivityResultRegistry.this.mPendingResults.remove(key);
                    callback.onActivityResult(contract.parseResult(pendingResult.getResultCode(), pendingResult.getData()));
                }
            }
        };
        lifecycleContainer.addObserver(observer);
        this.mKeyToLifecycleContainers.put(key, lifecycleContainer);
        return new ActivityResultLauncher<I>() { // from class: androidx.activity.result.ActivityResultRegistry.2
            @Override // androidx.activity.result.ActivityResultLauncher
            public void launch(I input, ActivityOptionsCompat options) {
                ActivityResultRegistry.this.mLaunchedKeys.add(key);
                Integer innerCode = ActivityResultRegistry.this.mKeyToRc.get(key);
                ActivityResultRegistry.this.onLaunch(innerCode != null ? innerCode.intValue() : requestCode, contract, input, options);
            }

            @Override // androidx.activity.result.ActivityResultLauncher
            public void unregister() {
                ActivityResultRegistry.this.unregister(key);
            }

            @Override // androidx.activity.result.ActivityResultLauncher
            public ActivityResultContract<I, ?> getContract() {
                return contract;
            }
        };
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final <I, O> ActivityResultLauncher<I> register(final String key, final ActivityResultContract<I, O> contract, ActivityResultCallback<O> callback) {
        final int requestCode = registerKey(key);
        this.mKeyToCallback.put(key, new CallbackAndContract<>(callback, contract));
        if (this.mParsedPendingResults.containsKey(key)) {
            Object obj = this.mParsedPendingResults.get(key);
            this.mParsedPendingResults.remove(key);
            callback.onActivityResult(obj);
        }
        ActivityResult pendingResult = (ActivityResult) this.mPendingResults.getParcelable(key);
        if (pendingResult != null) {
            this.mPendingResults.remove(key);
            callback.onActivityResult(contract.parseResult(pendingResult.getResultCode(), pendingResult.getData()));
        }
        return new ActivityResultLauncher<I>() { // from class: androidx.activity.result.ActivityResultRegistry.3
            @Override // androidx.activity.result.ActivityResultLauncher
            public void launch(I input, ActivityOptionsCompat options) {
                ActivityResultRegistry.this.mLaunchedKeys.add(key);
                Integer innerCode = ActivityResultRegistry.this.mKeyToRc.get(key);
                ActivityResultRegistry.this.onLaunch(innerCode != null ? innerCode.intValue() : requestCode, contract, input, options);
            }

            @Override // androidx.activity.result.ActivityResultLauncher
            public void unregister() {
                ActivityResultRegistry.this.unregister(key);
            }

            @Override // androidx.activity.result.ActivityResultLauncher
            public ActivityResultContract<I, ?> getContract() {
                return contract;
            }
        };
    }

    final void unregister(String key) {
        Integer rc;
        if (!this.mLaunchedKeys.contains(key) && (rc = this.mKeyToRc.remove(key)) != null) {
            this.mRcToKey.remove(rc);
        }
        this.mKeyToCallback.remove(key);
        if (this.mParsedPendingResults.containsKey(key)) {
            Log.w(LOG_TAG, "Dropping pending result for request " + key + ": " + this.mParsedPendingResults.get(key));
            this.mParsedPendingResults.remove(key);
        }
        if (this.mPendingResults.containsKey(key)) {
            Log.w(LOG_TAG, "Dropping pending result for request " + key + ": " + this.mPendingResults.getParcelable(key));
            this.mPendingResults.remove(key);
        }
        LifecycleContainer lifecycleContainer = this.mKeyToLifecycleContainers.get(key);
        if (lifecycleContainer != null) {
            lifecycleContainer.clearObservers();
            this.mKeyToLifecycleContainers.remove(key);
        }
    }

    public final void onSaveInstanceState(Bundle outState) {
        outState.putIntegerArrayList(KEY_COMPONENT_ACTIVITY_REGISTERED_RCS, new ArrayList<>(this.mKeyToRc.values()));
        outState.putStringArrayList(KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS, new ArrayList<>(this.mKeyToRc.keySet()));
        outState.putStringArrayList(KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS, new ArrayList<>(this.mLaunchedKeys));
        outState.putBundle(KEY_COMPONENT_ACTIVITY_PENDING_RESULTS, (Bundle) this.mPendingResults.clone());
        outState.putSerializable(KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT, this.mRandom);
    }

    public final void onRestoreInstanceState(Bundle savedInstanceState) {
        if (savedInstanceState == null) {
            return;
        }
        ArrayList<Integer> rcs = savedInstanceState.getIntegerArrayList(KEY_COMPONENT_ACTIVITY_REGISTERED_RCS);
        ArrayList<String> keys = savedInstanceState.getStringArrayList(KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS);
        if (keys == null || rcs == null) {
            return;
        }
        this.mLaunchedKeys = savedInstanceState.getStringArrayList(KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS);
        this.mRandom = (Random) savedInstanceState.getSerializable(KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT);
        this.mPendingResults.putAll(savedInstanceState.getBundle(KEY_COMPONENT_ACTIVITY_PENDING_RESULTS));
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            if (this.mKeyToRc.containsKey(key)) {
                Integer newRequestCode = this.mKeyToRc.remove(key);
                if (!this.mPendingResults.containsKey(key)) {
                    this.mRcToKey.remove(newRequestCode);
                }
            }
            Integer newRequestCode2 = rcs.get(i);
            bindRcKey(newRequestCode2.intValue(), keys.get(i));
        }
    }

    public final boolean dispatchResult(int requestCode, int resultCode, Intent data) {
        String key = this.mRcToKey.get(Integer.valueOf(requestCode));
        if (key == null) {
            return false;
        }
        this.mLaunchedKeys.remove(key);
        doDispatch(key, resultCode, data, this.mKeyToCallback.get(key));
        return true;
    }

    public final <O> boolean dispatchResult(int requestCode, O result) {
        String key = this.mRcToKey.get(Integer.valueOf(requestCode));
        if (key == null) {
            return false;
        }
        this.mLaunchedKeys.remove(key);
        CallbackAndContract<?> callbackAndContract = this.mKeyToCallback.get(key);
        if (callbackAndContract == null || callbackAndContract.mCallback == null) {
            this.mPendingResults.remove(key);
            this.mParsedPendingResults.put(key, result);
            return true;
        }
        callbackAndContract.mCallback.onActivityResult(result);
        return true;
    }

    private <O> void doDispatch(String key, int resultCode, Intent data, CallbackAndContract<O> callbackAndContract) {
        if (callbackAndContract != null && callbackAndContract.mCallback != null) {
            ActivityResultCallback<O> callback = callbackAndContract.mCallback;
            ActivityResultContract<?, O> contract = callbackAndContract.mContract;
            callback.onActivityResult(contract.parseResult(resultCode, data));
            return;
        }
        this.mParsedPendingResults.remove(key);
        this.mPendingResults.putParcelable(key, new ActivityResult(resultCode, data));
    }

    private int registerKey(String key) {
        Integer existing = this.mKeyToRc.get(key);
        if (existing != null) {
            return existing.intValue();
        }
        int rc = generateRandomNumber();
        bindRcKey(rc, key);
        return rc;
    }

    private int generateRandomNumber() {
        int number = this.mRandom.nextInt(2147418112) + 65536;
        while (this.mRcToKey.containsKey(Integer.valueOf(number))) {
            number = this.mRandom.nextInt(2147418112) + 65536;
        }
        return number;
    }

    private void bindRcKey(int rc, String key) {
        this.mRcToKey.put(Integer.valueOf(rc), key);
        this.mKeyToRc.put(key, Integer.valueOf(rc));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class CallbackAndContract<O> {
        final ActivityResultCallback<O> mCallback;
        final ActivityResultContract<?, O> mContract;

        CallbackAndContract(ActivityResultCallback<O> callback, ActivityResultContract<?, O> contract) {
            this.mCallback = callback;
            this.mContract = contract;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class LifecycleContainer {
        final Lifecycle mLifecycle;
        private final ArrayList<LifecycleEventObserver> mObservers = new ArrayList<>();

        LifecycleContainer(Lifecycle lifecycle) {
            this.mLifecycle = lifecycle;
        }

        void addObserver(LifecycleEventObserver observer) {
            this.mLifecycle.addObserver(observer);
            this.mObservers.add(observer);
        }

        void clearObservers() {
            Iterator<LifecycleEventObserver> it = this.mObservers.iterator();
            while (it.hasNext()) {
                LifecycleEventObserver observer = it.next();
                this.mLifecycle.removeObserver(observer);
            }
            this.mObservers.clear();
        }
    }
}
