package androidx.lifecycle;

import androidx.arch.core.util.Function;
/* loaded from: classes.dex */
public class Transformations {
    private Transformations() {
    }

    public static <X, Y> LiveData<Y> map(LiveData<X> source, final Function<X, Y> mapFunction) {
        final MediatorLiveData<Y> result = new MediatorLiveData<>();
        result.addSource(source, new Observer<X>() { // from class: androidx.lifecycle.Transformations.1
            @Override // androidx.lifecycle.Observer
            public void onChanged(X x) {
                MediatorLiveData.this.setValue(mapFunction.apply(x));
            }
        });
        return result;
    }

    public static <X, Y> LiveData<Y> switchMap(LiveData<X> source, final Function<X, LiveData<Y>> switchMapFunction) {
        final MediatorLiveData<Y> result = new MediatorLiveData<>();
        result.addSource(source, new Observer<X>() { // from class: androidx.lifecycle.Transformations.2
            LiveData<Y> mSource;

            @Override // androidx.lifecycle.Observer
            public void onChanged(X x) {
                LiveData<Y> newLiveData = (LiveData) Function.this.apply(x);
                Object obj = this.mSource;
                if (obj == newLiveData) {
                    return;
                }
                if (obj != null) {
                    result.removeSource(obj);
                }
                this.mSource = newLiveData;
                if (newLiveData != 0) {
                    result.addSource(newLiveData, new Observer<Y>() { // from class: androidx.lifecycle.Transformations.2.1
                        @Override // androidx.lifecycle.Observer
                        public void onChanged(Y y) {
                            result.setValue(y);
                        }
                    });
                }
            }
        });
        return result;
    }
}
