package androidx.lifecycle;

import android.app.Application;
import java.lang.reflect.InvocationTargetException;
/* loaded from: classes.dex */
public class ViewModelProvider {
    private static final String DEFAULT_KEY = "androidx.lifecycle.ViewModelProvider.DefaultKey";
    private final Factory mFactory;
    private final ViewModelStore mViewModelStore;

    /* loaded from: classes.dex */
    public interface Factory {
        <T extends ViewModel> T create(Class<T> cls);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class OnRequeryFactory {
        OnRequeryFactory() {
        }

        void onRequery(ViewModel viewModel) {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static abstract class KeyedFactory extends OnRequeryFactory implements Factory {
        public abstract <T extends ViewModel> T create(String str, Class<T> cls);

        public <T extends ViewModel> T create(Class<T> modelClass) {
            throw new UnsupportedOperationException("create(String, Class<?>) must be called on implementaions of KeyedFactory");
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public ViewModelProvider(androidx.lifecycle.ViewModelStoreOwner r3) {
        /*
            r2 = this;
            androidx.lifecycle.ViewModelStore r0 = r3.getViewModelStore()
            boolean r1 = r3 instanceof androidx.lifecycle.HasDefaultViewModelProviderFactory
            if (r1 == 0) goto L10
            r1 = r3
            androidx.lifecycle.HasDefaultViewModelProviderFactory r1 = (androidx.lifecycle.HasDefaultViewModelProviderFactory) r1
            androidx.lifecycle.ViewModelProvider$Factory r1 = r1.getDefaultViewModelProviderFactory()
            goto L14
        L10:
            androidx.lifecycle.ViewModelProvider$NewInstanceFactory r1 = androidx.lifecycle.ViewModelProvider.NewInstanceFactory.getInstance()
        L14:
            r2.<init>(r0, r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.ViewModelProvider.<init>(androidx.lifecycle.ViewModelStoreOwner):void");
    }

    public ViewModelProvider(ViewModelStoreOwner owner, Factory factory) {
        this(owner.getViewModelStore(), factory);
    }

    public ViewModelProvider(ViewModelStore store, Factory factory) {
        this.mFactory = factory;
        this.mViewModelStore = store;
    }

    public <T extends ViewModel> T get(Class<T> modelClass) {
        String canonicalName = modelClass.getCanonicalName();
        if (canonicalName == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        return (T) get("androidx.lifecycle.ViewModelProvider.DefaultKey:" + canonicalName, modelClass);
    }

    public <T extends ViewModel> T get(String key, Class<T> modelClass) {
        ViewModel viewModel;
        T t = (T) this.mViewModelStore.get(key);
        if (modelClass.isInstance(t)) {
            Factory factory = this.mFactory;
            if (factory instanceof OnRequeryFactory) {
                ((OnRequeryFactory) factory).onRequery(t);
            }
            return t;
        }
        Factory factory2 = this.mFactory;
        if (factory2 instanceof KeyedFactory) {
            ViewModel viewModel2 = ((KeyedFactory) factory2).create(key, modelClass);
            viewModel = (T) viewModel2;
        } else {
            ViewModel viewModel3 = factory2.create(modelClass);
            viewModel = (T) viewModel3;
        }
        this.mViewModelStore.put(key, viewModel);
        return (T) viewModel;
    }

    /* loaded from: classes.dex */
    public static class NewInstanceFactory implements Factory {
        private static NewInstanceFactory sInstance;

        /* JADX INFO: Access modifiers changed from: package-private */
        public static NewInstanceFactory getInstance() {
            if (sInstance == null) {
                sInstance = new NewInstanceFactory();
            }
            return sInstance;
        }

        @Override // androidx.lifecycle.ViewModelProvider.Factory
        public <T extends ViewModel> T create(Class<T> modelClass) {
            try {
                return modelClass.newInstance();
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Cannot create an instance of " + modelClass, e);
            } catch (InstantiationException e2) {
                throw new RuntimeException("Cannot create an instance of " + modelClass, e2);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class AndroidViewModelFactory extends NewInstanceFactory {
        private static AndroidViewModelFactory sInstance;
        private Application mApplication;

        public static AndroidViewModelFactory getInstance(Application application) {
            if (sInstance == null) {
                sInstance = new AndroidViewModelFactory(application);
            }
            return sInstance;
        }

        public AndroidViewModelFactory(Application application) {
            this.mApplication = application;
        }

        @Override // androidx.lifecycle.ViewModelProvider.NewInstanceFactory, androidx.lifecycle.ViewModelProvider.Factory
        public <T extends ViewModel> T create(Class<T> modelClass) {
            if (AndroidViewModel.class.isAssignableFrom(modelClass)) {
                try {
                    return modelClass.getConstructor(Application.class).newInstance(this.mApplication);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException("Cannot create an instance of " + modelClass, e);
                } catch (InstantiationException e2) {
                    throw new RuntimeException("Cannot create an instance of " + modelClass, e2);
                } catch (NoSuchMethodException e3) {
                    throw new RuntimeException("Cannot create an instance of " + modelClass, e3);
                } catch (InvocationTargetException e4) {
                    throw new RuntimeException("Cannot create an instance of " + modelClass, e4);
                }
            }
            return (T) super.create(modelClass);
        }
    }
}
