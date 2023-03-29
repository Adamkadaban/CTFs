package androidx.core.provider;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import androidx.collection.LruCache;
import androidx.collection.SimpleArrayMap;
import androidx.core.graphics.TypefaceCompat;
import androidx.core.provider.FontsContractCompat;
import androidx.core.util.Consumer;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FontRequestWorker {
    static final LruCache<String, Typeface> sTypefaceCache = new LruCache<>(16);
    private static final ExecutorService DEFAULT_EXECUTOR_SERVICE = RequestExecutor.createDefaultExecutor("fonts-androidx", 10, 10000);
    static final Object LOCK = new Object();
    static final SimpleArrayMap<String, ArrayList<Consumer<TypefaceResult>>> PENDING_REPLIES = new SimpleArrayMap<>();

    private FontRequestWorker() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void resetTypefaceCache() {
        sTypefaceCache.evictAll();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Typeface requestFontSync(final Context context, final FontRequest request, CallbackWithHandler callback, final int style, int timeoutInMillis) {
        final String id = createCacheId(request, style);
        Typeface cached = sTypefaceCache.get(id);
        if (cached != null) {
            callback.onTypefaceResult(new TypefaceResult(cached));
            return cached;
        } else if (timeoutInMillis == -1) {
            TypefaceResult typefaceResult = getFontSync(id, context, request, style);
            callback.onTypefaceResult(typefaceResult);
            return typefaceResult.mTypeface;
        } else {
            Callable<TypefaceResult> fetcher = new Callable<TypefaceResult>() { // from class: androidx.core.provider.FontRequestWorker.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.util.concurrent.Callable
                public TypefaceResult call() {
                    return FontRequestWorker.getFontSync(id, context, request, style);
                }
            };
            try {
                TypefaceResult typefaceResult2 = (TypefaceResult) RequestExecutor.submit(DEFAULT_EXECUTOR_SERVICE, fetcher, timeoutInMillis);
                callback.onTypefaceResult(typefaceResult2);
                return typefaceResult2.mTypeface;
            } catch (InterruptedException e) {
                callback.onTypefaceResult(new TypefaceResult(-3));
                return null;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Typeface requestFontAsync(final Context context, final FontRequest request, final int style, Executor executor, final CallbackWithHandler callback) {
        final String id = createCacheId(request, style);
        Typeface cached = sTypefaceCache.get(id);
        if (cached != null) {
            callback.onTypefaceResult(new TypefaceResult(cached));
            return cached;
        }
        Consumer<TypefaceResult> reply = new Consumer<TypefaceResult>() { // from class: androidx.core.provider.FontRequestWorker.2
            @Override // androidx.core.util.Consumer
            public void accept(TypefaceResult typefaceResult) {
                if (typefaceResult == null) {
                    typefaceResult = new TypefaceResult(-3);
                }
                CallbackWithHandler.this.onTypefaceResult(typefaceResult);
            }
        };
        synchronized (LOCK) {
            SimpleArrayMap<String, ArrayList<Consumer<TypefaceResult>>> simpleArrayMap = PENDING_REPLIES;
            ArrayList<Consumer<TypefaceResult>> pendingReplies = simpleArrayMap.get(id);
            if (pendingReplies != null) {
                pendingReplies.add(reply);
                return null;
            }
            ArrayList<Consumer<TypefaceResult>> pendingReplies2 = new ArrayList<>();
            pendingReplies2.add(reply);
            simpleArrayMap.put(id, pendingReplies2);
            Callable<TypefaceResult> fetcher = new Callable<TypefaceResult>() { // from class: androidx.core.provider.FontRequestWorker.3
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.util.concurrent.Callable
                public TypefaceResult call() {
                    try {
                        return FontRequestWorker.getFontSync(id, context, request, style);
                    } catch (Throwable th) {
                        return new TypefaceResult(-3);
                    }
                }
            };
            Executor finalExecutor = executor == null ? DEFAULT_EXECUTOR_SERVICE : executor;
            RequestExecutor.execute(finalExecutor, fetcher, new Consumer<TypefaceResult>() { // from class: androidx.core.provider.FontRequestWorker.4
                @Override // androidx.core.util.Consumer
                public void accept(TypefaceResult typefaceResult) {
                    synchronized (FontRequestWorker.LOCK) {
                        ArrayList<Consumer<TypefaceResult>> replies = FontRequestWorker.PENDING_REPLIES.get(id);
                        if (replies == null) {
                            return;
                        }
                        FontRequestWorker.PENDING_REPLIES.remove(id);
                        for (int i = 0; i < replies.size(); i++) {
                            replies.get(i).accept(typefaceResult);
                        }
                    }
                }
            });
            return null;
        }
    }

    private static String createCacheId(FontRequest request, int style) {
        return request.getId() + "-" + style;
    }

    static TypefaceResult getFontSync(String cacheId, Context context, FontRequest request, int style) {
        LruCache<String, Typeface> lruCache = sTypefaceCache;
        Typeface cached = lruCache.get(cacheId);
        if (cached != null) {
            return new TypefaceResult(cached);
        }
        try {
            FontsContractCompat.FontFamilyResult result = FontProvider.getFontFamilyResult(context, request, null);
            int fontFamilyResultStatus = getFontFamilyResultStatus(result);
            if (fontFamilyResultStatus != 0) {
                return new TypefaceResult(fontFamilyResultStatus);
            }
            Typeface typeface = TypefaceCompat.createFromFontInfo(context, null, result.getFonts(), style);
            if (typeface != null) {
                lruCache.put(cacheId, typeface);
                return new TypefaceResult(typeface);
            }
            return new TypefaceResult(-3);
        } catch (PackageManager.NameNotFoundException e) {
            return new TypefaceResult(-1);
        }
    }

    private static int getFontFamilyResultStatus(FontsContractCompat.FontFamilyResult fontFamilyResult) {
        if (fontFamilyResult.getStatusCode() != 0) {
            switch (fontFamilyResult.getStatusCode()) {
                case 1:
                    return -2;
                default:
                    return -3;
            }
        }
        FontsContractCompat.FontInfo[] fonts = fontFamilyResult.getFonts();
        if (fonts == null || fonts.length == 0) {
            return 1;
        }
        for (FontsContractCompat.FontInfo font : fonts) {
            int resultCode = font.getResultCode();
            if (resultCode != 0) {
                if (resultCode < 0) {
                    return -3;
                } else {
                    return resultCode;
                }
            }
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class TypefaceResult {
        final int mResult;
        final Typeface mTypeface;

        TypefaceResult(int result) {
            this.mTypeface = null;
            this.mResult = result;
        }

        TypefaceResult(Typeface typeface) {
            this.mTypeface = typeface;
            this.mResult = 0;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean isSuccess() {
            return this.mResult == 0;
        }
    }
}
