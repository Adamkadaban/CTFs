package androidx.emoji2.text;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import androidx.collection.ArraySet;
import androidx.core.util.Preconditions;
import androidx.emoji2.text.DefaultEmojiCompatConfig;
import androidx.emoji2.text.EmojiProcessor;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
/* loaded from: classes.dex */
public class EmojiCompat {
    public static final String EDITOR_INFO_METAVERSION_KEY = "android.support.text.emoji.emojiCompat_metadataVersion";
    public static final String EDITOR_INFO_REPLACE_ALL_KEY = "android.support.text.emoji.emojiCompat_replaceAll";
    static final int EMOJI_COUNT_UNLIMITED = Integer.MAX_VALUE;
    public static final int LOAD_STATE_DEFAULT = 3;
    public static final int LOAD_STATE_FAILED = 2;
    public static final int LOAD_STATE_LOADING = 0;
    public static final int LOAD_STATE_SUCCEEDED = 1;
    public static final int LOAD_STRATEGY_DEFAULT = 0;
    public static final int LOAD_STRATEGY_MANUAL = 1;
    private static final String NOT_INITIALIZED_ERROR_TEXT = "EmojiCompat is not initialized.\n\nYou must initialize EmojiCompat prior to referencing the EmojiCompat instance.\n\nThe most likely cause of this error is disabling the EmojiCompatInitializer\neither explicitly in AndroidManifest.xml, or by including\nandroidx.emoji2:emoji2-bundled.\n\nAutomatic initialization is typically performed by EmojiCompatInitializer. If\nyou are not expecting to initialize EmojiCompat manually in your application,\nplease check to ensure it has not been removed from your APK's manifest. You can\ndo this in Android Studio using Build > Analyze APK.\n\nIn the APK Analyzer, ensure that the startup entry for\nEmojiCompatInitializer and InitializationProvider is present in\n AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you\nintend to use automatic configuration, verify:\n\n  1. Your application does not include emoji2-bundled\n  2. All modules do not contain an exclusion manifest rule for\n     EmojiCompatInitializer or InitializationProvider. For more information\n     about manifest exclusions see the documentation for the androidx startup\n     library.\n\nIf you intend to use emoji2-bundled, please call EmojiCompat.init. You can\nlearn more in the documentation for BundledEmojiCompatConfig.\n\nIf you intended to perform manual configuration, it is recommended that you call\nEmojiCompat.init immediately on application startup.\n\nIf you still cannot resolve this issue, please open a bug with your specific\nconfiguration to help improve error message.";
    public static final int REPLACE_STRATEGY_ALL = 1;
    public static final int REPLACE_STRATEGY_DEFAULT = 0;
    public static final int REPLACE_STRATEGY_NON_EXISTENT = 2;
    private static volatile boolean sHasDoneDefaultConfigLookup;
    private static volatile EmojiCompat sInstance;
    final int[] mEmojiAsDefaultStyleExceptions;
    private final int mEmojiSpanIndicatorColor;
    private final boolean mEmojiSpanIndicatorEnabled;
    private final GlyphChecker mGlyphChecker;
    private final CompatInternal mHelper;
    private final Set<InitCallback> mInitCallbacks;
    private final ReadWriteLock mInitLock = new ReentrantReadWriteLock();
    private volatile int mLoadState = 3;
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final int mMetadataLoadStrategy;
    final MetadataRepoLoader mMetadataLoader;
    final boolean mReplaceAll;
    final boolean mUseEmojiAsDefaultStyle;
    private static final Object INSTANCE_LOCK = new Object();
    private static final Object CONFIG_LOCK = new Object();

    /* loaded from: classes.dex */
    public interface GlyphChecker {
        boolean hasGlyph(CharSequence charSequence, int i, int i2, int i3);
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface LoadStrategy {
    }

    /* loaded from: classes.dex */
    public interface MetadataRepoLoader {
        void load(MetadataRepoLoaderCallback metadataRepoLoaderCallback);
    }

    /* loaded from: classes.dex */
    public static abstract class MetadataRepoLoaderCallback {
        public abstract void onFailed(Throwable th);

        public abstract void onLoaded(MetadataRepo metadataRepo);
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface ReplaceStrategy {
    }

    private EmojiCompat(Config config) {
        this.mReplaceAll = config.mReplaceAll;
        this.mUseEmojiAsDefaultStyle = config.mUseEmojiAsDefaultStyle;
        this.mEmojiAsDefaultStyleExceptions = config.mEmojiAsDefaultStyleExceptions;
        this.mEmojiSpanIndicatorEnabled = config.mEmojiSpanIndicatorEnabled;
        this.mEmojiSpanIndicatorColor = config.mEmojiSpanIndicatorColor;
        this.mMetadataLoader = config.mMetadataLoader;
        this.mMetadataLoadStrategy = config.mMetadataLoadStrategy;
        this.mGlyphChecker = config.mGlyphChecker;
        ArraySet arraySet = new ArraySet();
        this.mInitCallbacks = arraySet;
        if (config.mInitCallbacks != null && !config.mInitCallbacks.isEmpty()) {
            arraySet.addAll(config.mInitCallbacks);
        }
        this.mHelper = Build.VERSION.SDK_INT < 19 ? new CompatInternal(this) : new CompatInternal19(this);
        loadMetadata();
    }

    public static EmojiCompat init(Context context) {
        return init(context, null);
    }

    public static EmojiCompat init(Context context, DefaultEmojiCompatConfig.DefaultEmojiCompatConfigFactory defaultFactory) {
        EmojiCompat emojiCompat;
        if (sHasDoneDefaultConfigLookup) {
            return sInstance;
        }
        DefaultEmojiCompatConfig.DefaultEmojiCompatConfigFactory factory = defaultFactory != null ? defaultFactory : new DefaultEmojiCompatConfig.DefaultEmojiCompatConfigFactory(null);
        Config config = factory.create(context);
        synchronized (CONFIG_LOCK) {
            if (!sHasDoneDefaultConfigLookup) {
                if (config != null) {
                    init(config);
                }
                sHasDoneDefaultConfigLookup = true;
            }
            emojiCompat = sInstance;
        }
        return emojiCompat;
    }

    public static EmojiCompat init(Config config) {
        EmojiCompat localInstance = sInstance;
        if (localInstance == null) {
            synchronized (INSTANCE_LOCK) {
                localInstance = sInstance;
                if (localInstance == null) {
                    localInstance = new EmojiCompat(config);
                    sInstance = localInstance;
                }
            }
        }
        return localInstance;
    }

    public static boolean isConfigured() {
        return sInstance != null;
    }

    public static EmojiCompat reset(Config config) {
        EmojiCompat localInstance;
        synchronized (INSTANCE_LOCK) {
            localInstance = new EmojiCompat(config);
            sInstance = localInstance;
        }
        return localInstance;
    }

    public static EmojiCompat reset(EmojiCompat emojiCompat) {
        EmojiCompat emojiCompat2;
        synchronized (INSTANCE_LOCK) {
            sInstance = emojiCompat;
            emojiCompat2 = sInstance;
        }
        return emojiCompat2;
    }

    public static void skipDefaultConfigurationLookup(boolean shouldSkip) {
        synchronized (CONFIG_LOCK) {
            sHasDoneDefaultConfigLookup = shouldSkip;
        }
    }

    public static EmojiCompat get() {
        EmojiCompat localInstance;
        synchronized (INSTANCE_LOCK) {
            localInstance = sInstance;
            Preconditions.checkState(localInstance != null, NOT_INITIALIZED_ERROR_TEXT);
        }
        return localInstance;
    }

    public void load() {
        Preconditions.checkState(this.mMetadataLoadStrategy == 1, "Set metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading");
        if (isInitialized()) {
            return;
        }
        this.mInitLock.writeLock().lock();
        try {
            if (this.mLoadState == 0) {
                return;
            }
            this.mLoadState = 0;
            this.mInitLock.writeLock().unlock();
            this.mHelper.loadMetadata();
        } finally {
            this.mInitLock.writeLock().unlock();
        }
    }

    private void loadMetadata() {
        this.mInitLock.writeLock().lock();
        try {
            if (this.mMetadataLoadStrategy == 0) {
                this.mLoadState = 0;
            }
            this.mInitLock.writeLock().unlock();
            if (getLoadState() == 0) {
                this.mHelper.loadMetadata();
            }
        } catch (Throwable th) {
            this.mInitLock.writeLock().unlock();
            throw th;
        }
    }

    void onMetadataLoadSuccess() {
        Collection<InitCallback> initCallbacks = new ArrayList<>();
        this.mInitLock.writeLock().lock();
        try {
            this.mLoadState = 1;
            initCallbacks.addAll(this.mInitCallbacks);
            this.mInitCallbacks.clear();
            this.mInitLock.writeLock().unlock();
            this.mMainHandler.post(new ListenerDispatcher(initCallbacks, this.mLoadState));
        } catch (Throwable th) {
            this.mInitLock.writeLock().unlock();
            throw th;
        }
    }

    void onMetadataLoadFailed(Throwable throwable) {
        Collection<InitCallback> initCallbacks = new ArrayList<>();
        this.mInitLock.writeLock().lock();
        try {
            this.mLoadState = 2;
            initCallbacks.addAll(this.mInitCallbacks);
            this.mInitCallbacks.clear();
            this.mInitLock.writeLock().unlock();
            this.mMainHandler.post(new ListenerDispatcher(initCallbacks, this.mLoadState, throwable));
        } catch (Throwable th) {
            this.mInitLock.writeLock().unlock();
            throw th;
        }
    }

    public void registerInitCallback(InitCallback initCallback) {
        Preconditions.checkNotNull(initCallback, "initCallback cannot be null");
        this.mInitLock.writeLock().lock();
        try {
            if (this.mLoadState != 1 && this.mLoadState != 2) {
                this.mInitCallbacks.add(initCallback);
            }
            this.mMainHandler.post(new ListenerDispatcher(initCallback, this.mLoadState));
        } finally {
            this.mInitLock.writeLock().unlock();
        }
    }

    public void unregisterInitCallback(InitCallback initCallback) {
        Preconditions.checkNotNull(initCallback, "initCallback cannot be null");
        this.mInitLock.writeLock().lock();
        try {
            this.mInitCallbacks.remove(initCallback);
        } finally {
            this.mInitLock.writeLock().unlock();
        }
    }

    public int getLoadState() {
        this.mInitLock.readLock().lock();
        try {
            return this.mLoadState;
        } finally {
            this.mInitLock.readLock().unlock();
        }
    }

    private boolean isInitialized() {
        return getLoadState() == 1;
    }

    public boolean isEmojiSpanIndicatorEnabled() {
        return this.mEmojiSpanIndicatorEnabled;
    }

    public int getEmojiSpanIndicatorColor() {
        return this.mEmojiSpanIndicatorColor;
    }

    public static boolean handleOnKeyDown(Editable editable, int keyCode, KeyEvent event) {
        if (Build.VERSION.SDK_INT >= 19) {
            return EmojiProcessor.handleOnKeyDown(editable, keyCode, event);
        }
        return false;
    }

    public static boolean handleDeleteSurroundingText(InputConnection inputConnection, Editable editable, int beforeLength, int afterLength, boolean inCodePoints) {
        if (Build.VERSION.SDK_INT >= 19) {
            return EmojiProcessor.handleDeleteSurroundingText(inputConnection, editable, beforeLength, afterLength, inCodePoints);
        }
        return false;
    }

    public boolean hasEmojiGlyph(CharSequence sequence) {
        Preconditions.checkState(isInitialized(), "Not initialized yet");
        Preconditions.checkNotNull(sequence, "sequence cannot be null");
        return this.mHelper.hasEmojiGlyph(sequence);
    }

    public boolean hasEmojiGlyph(CharSequence sequence, int metadataVersion) {
        Preconditions.checkState(isInitialized(), "Not initialized yet");
        Preconditions.checkNotNull(sequence, "sequence cannot be null");
        return this.mHelper.hasEmojiGlyph(sequence, metadataVersion);
    }

    public CharSequence process(CharSequence charSequence) {
        int length = charSequence == null ? 0 : charSequence.length();
        return process(charSequence, 0, length);
    }

    public CharSequence process(CharSequence charSequence, int start, int end) {
        return process(charSequence, start, end, Integer.MAX_VALUE);
    }

    public CharSequence process(CharSequence charSequence, int start, int end, int maxEmojiCount) {
        return process(charSequence, start, end, maxEmojiCount, 0);
    }

    public CharSequence process(CharSequence charSequence, int start, int end, int maxEmojiCount, int replaceStrategy) {
        boolean replaceAll;
        Preconditions.checkState(isInitialized(), "Not initialized yet");
        Preconditions.checkArgumentNonnegative(start, "start cannot be negative");
        Preconditions.checkArgumentNonnegative(end, "end cannot be negative");
        Preconditions.checkArgumentNonnegative(maxEmojiCount, "maxEmojiCount cannot be negative");
        Preconditions.checkArgument(start <= end, "start should be <= than end");
        if (charSequence == null) {
            return null;
        }
        Preconditions.checkArgument(start <= charSequence.length(), "start should be < than charSequence length");
        Preconditions.checkArgument(end <= charSequence.length(), "end should be < than charSequence length");
        if (charSequence.length() == 0 || start == end) {
            return charSequence;
        }
        switch (replaceStrategy) {
            case 1:
                replaceAll = true;
                break;
            case 2:
                replaceAll = false;
                break;
            default:
                replaceAll = this.mReplaceAll;
                break;
        }
        return this.mHelper.process(charSequence, start, end, maxEmojiCount, replaceAll);
    }

    public String getAssetSignature() {
        Preconditions.checkState(isInitialized(), "Not initialized yet");
        return this.mHelper.getAssetSignature();
    }

    public void updateEditorInfo(EditorInfo outAttrs) {
        if (!isInitialized() || outAttrs == null) {
            return;
        }
        if (outAttrs.extras == null) {
            outAttrs.extras = new Bundle();
        }
        this.mHelper.updateEditorInfoAttrs(outAttrs);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class SpanFactory {
        SpanFactory() {
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public EmojiSpan createSpan(EmojiMetadata metadata) {
            return new TypefaceEmojiSpan(metadata);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class InitCallback {
        public void onInitialized() {
        }

        public void onFailed(Throwable throwable) {
        }
    }

    /* loaded from: classes.dex */
    public static abstract class Config {
        int[] mEmojiAsDefaultStyleExceptions;
        boolean mEmojiSpanIndicatorEnabled;
        Set<InitCallback> mInitCallbacks;
        final MetadataRepoLoader mMetadataLoader;
        boolean mReplaceAll;
        boolean mUseEmojiAsDefaultStyle;
        int mEmojiSpanIndicatorColor = -16711936;
        int mMetadataLoadStrategy = 0;
        GlyphChecker mGlyphChecker = new EmojiProcessor.DefaultGlyphChecker();

        /* JADX INFO: Access modifiers changed from: protected */
        public Config(MetadataRepoLoader metadataLoader) {
            Preconditions.checkNotNull(metadataLoader, "metadataLoader cannot be null.");
            this.mMetadataLoader = metadataLoader;
        }

        public Config registerInitCallback(InitCallback initCallback) {
            Preconditions.checkNotNull(initCallback, "initCallback cannot be null");
            if (this.mInitCallbacks == null) {
                this.mInitCallbacks = new ArraySet();
            }
            this.mInitCallbacks.add(initCallback);
            return this;
        }

        public Config unregisterInitCallback(InitCallback initCallback) {
            Preconditions.checkNotNull(initCallback, "initCallback cannot be null");
            Set<InitCallback> set = this.mInitCallbacks;
            if (set != null) {
                set.remove(initCallback);
            }
            return this;
        }

        public Config setReplaceAll(boolean replaceAll) {
            this.mReplaceAll = replaceAll;
            return this;
        }

        public Config setUseEmojiAsDefaultStyle(boolean useEmojiAsDefaultStyle) {
            return setUseEmojiAsDefaultStyle(useEmojiAsDefaultStyle, null);
        }

        public Config setUseEmojiAsDefaultStyle(boolean useEmojiAsDefaultStyle, List<Integer> emojiAsDefaultStyleExceptions) {
            this.mUseEmojiAsDefaultStyle = useEmojiAsDefaultStyle;
            if (useEmojiAsDefaultStyle && emojiAsDefaultStyleExceptions != null) {
                this.mEmojiAsDefaultStyleExceptions = new int[emojiAsDefaultStyleExceptions.size()];
                int i = 0;
                for (Integer exception : emojiAsDefaultStyleExceptions) {
                    this.mEmojiAsDefaultStyleExceptions[i] = exception.intValue();
                    i++;
                }
                Arrays.sort(this.mEmojiAsDefaultStyleExceptions);
            } else {
                this.mEmojiAsDefaultStyleExceptions = null;
            }
            return this;
        }

        public Config setEmojiSpanIndicatorEnabled(boolean emojiSpanIndicatorEnabled) {
            this.mEmojiSpanIndicatorEnabled = emojiSpanIndicatorEnabled;
            return this;
        }

        public Config setEmojiSpanIndicatorColor(int color) {
            this.mEmojiSpanIndicatorColor = color;
            return this;
        }

        public Config setMetadataLoadStrategy(int strategy) {
            this.mMetadataLoadStrategy = strategy;
            return this;
        }

        public Config setGlyphChecker(GlyphChecker glyphChecker) {
            Preconditions.checkNotNull(glyphChecker, "GlyphChecker cannot be null");
            this.mGlyphChecker = glyphChecker;
            return this;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public final MetadataRepoLoader getMetadataRepoLoader() {
            return this.mMetadataLoader;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ListenerDispatcher implements Runnable {
        private final List<InitCallback> mInitCallbacks;
        private final int mLoadState;
        private final Throwable mThrowable;

        ListenerDispatcher(InitCallback initCallback, int loadState) {
            this(Arrays.asList((InitCallback) Preconditions.checkNotNull(initCallback, "initCallback cannot be null")), loadState, null);
        }

        ListenerDispatcher(Collection<InitCallback> initCallbacks, int loadState) {
            this(initCallbacks, loadState, null);
        }

        ListenerDispatcher(Collection<InitCallback> initCallbacks, int loadState, Throwable throwable) {
            Preconditions.checkNotNull(initCallbacks, "initCallbacks cannot be null");
            this.mInitCallbacks = new ArrayList(initCallbacks);
            this.mLoadState = loadState;
            this.mThrowable = throwable;
        }

        @Override // java.lang.Runnable
        public void run() {
            int size = this.mInitCallbacks.size();
            switch (this.mLoadState) {
                case 1:
                    for (int i = 0; i < size; i++) {
                        this.mInitCallbacks.get(i).onInitialized();
                    }
                    return;
                default:
                    for (int i2 = 0; i2 < size; i2++) {
                        this.mInitCallbacks.get(i2).onFailed(this.mThrowable);
                    }
                    return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class CompatInternal {
        final EmojiCompat mEmojiCompat;

        CompatInternal(EmojiCompat emojiCompat) {
            this.mEmojiCompat = emojiCompat;
        }

        void loadMetadata() {
            this.mEmojiCompat.onMetadataLoadSuccess();
        }

        boolean hasEmojiGlyph(CharSequence sequence) {
            return false;
        }

        boolean hasEmojiGlyph(CharSequence sequence, int metadataVersion) {
            return false;
        }

        CharSequence process(CharSequence charSequence, int start, int end, int maxEmojiCount, boolean replaceAll) {
            return charSequence;
        }

        void updateEditorInfoAttrs(EditorInfo outAttrs) {
        }

        String getAssetSignature() {
            return "";
        }
    }

    /* loaded from: classes.dex */
    private static final class CompatInternal19 extends CompatInternal {
        private volatile MetadataRepo mMetadataRepo;
        private volatile EmojiProcessor mProcessor;

        CompatInternal19(EmojiCompat emojiCompat) {
            super(emojiCompat);
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        void loadMetadata() {
            try {
                MetadataRepoLoaderCallback callback = new MetadataRepoLoaderCallback() { // from class: androidx.emoji2.text.EmojiCompat.CompatInternal19.1
                    @Override // androidx.emoji2.text.EmojiCompat.MetadataRepoLoaderCallback
                    public void onLoaded(MetadataRepo metadataRepo) {
                        CompatInternal19.this.onMetadataLoadSuccess(metadataRepo);
                    }

                    @Override // androidx.emoji2.text.EmojiCompat.MetadataRepoLoaderCallback
                    public void onFailed(Throwable throwable) {
                        CompatInternal19.this.mEmojiCompat.onMetadataLoadFailed(throwable);
                    }
                };
                this.mEmojiCompat.mMetadataLoader.load(callback);
            } catch (Throwable t) {
                this.mEmojiCompat.onMetadataLoadFailed(t);
            }
        }

        void onMetadataLoadSuccess(MetadataRepo metadataRepo) {
            if (metadataRepo == null) {
                this.mEmojiCompat.onMetadataLoadFailed(new IllegalArgumentException("metadataRepo cannot be null"));
                return;
            }
            this.mMetadataRepo = metadataRepo;
            this.mProcessor = new EmojiProcessor(this.mMetadataRepo, new SpanFactory(), this.mEmojiCompat.mGlyphChecker, this.mEmojiCompat.mUseEmojiAsDefaultStyle, this.mEmojiCompat.mEmojiAsDefaultStyleExceptions);
            this.mEmojiCompat.onMetadataLoadSuccess();
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        boolean hasEmojiGlyph(CharSequence sequence) {
            return this.mProcessor.getEmojiMetadata(sequence) != null;
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        boolean hasEmojiGlyph(CharSequence sequence, int metadataVersion) {
            EmojiMetadata emojiMetadata = this.mProcessor.getEmojiMetadata(sequence);
            return emojiMetadata != null && emojiMetadata.getCompatAdded() <= metadataVersion;
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        CharSequence process(CharSequence charSequence, int start, int end, int maxEmojiCount, boolean replaceAll) {
            return this.mProcessor.process(charSequence, start, end, maxEmojiCount, replaceAll);
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        void updateEditorInfoAttrs(EditorInfo outAttrs) {
            outAttrs.extras.putInt(EmojiCompat.EDITOR_INFO_METAVERSION_KEY, this.mMetadataRepo.getMetadataVersion());
            outAttrs.extras.putBoolean(EmojiCompat.EDITOR_INFO_REPLACE_ALL_KEY, this.mEmojiCompat.mReplaceAll);
        }

        @Override // androidx.emoji2.text.EmojiCompat.CompatInternal
        String getAssetSignature() {
            String sha = this.mMetadataRepo.getMetadataList().sourceSha();
            return sha == null ? "" : sha;
        }
    }
}
