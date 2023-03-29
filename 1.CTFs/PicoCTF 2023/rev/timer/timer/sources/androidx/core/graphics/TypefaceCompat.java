package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import androidx.collection.LruCache;
import androidx.core.content.res.FontResourcesParserCompat;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.provider.FontsContractCompat;
/* loaded from: classes.dex */
public class TypefaceCompat {
    private static final LruCache<String, Typeface> sTypefaceCache;
    private static final TypefaceCompatBaseImpl sTypefaceCompatImpl;

    static {
        if (Build.VERSION.SDK_INT >= 29) {
            sTypefaceCompatImpl = new TypefaceCompatApi29Impl();
        } else if (Build.VERSION.SDK_INT >= 28) {
            sTypefaceCompatImpl = new TypefaceCompatApi28Impl();
        } else if (Build.VERSION.SDK_INT >= 26) {
            sTypefaceCompatImpl = new TypefaceCompatApi26Impl();
        } else if (Build.VERSION.SDK_INT >= 24 && TypefaceCompatApi24Impl.isUsable()) {
            sTypefaceCompatImpl = new TypefaceCompatApi24Impl();
        } else if (Build.VERSION.SDK_INT >= 21) {
            sTypefaceCompatImpl = new TypefaceCompatApi21Impl();
        } else {
            sTypefaceCompatImpl = new TypefaceCompatBaseImpl();
        }
        sTypefaceCache = new LruCache<>(16);
    }

    private TypefaceCompat() {
    }

    public static Typeface findFromCache(Resources resources, int id, int style) {
        return sTypefaceCache.get(createResourceUid(resources, id, style));
    }

    private static String createResourceUid(Resources resources, int id, int style) {
        return resources.getResourcePackageName(id) + "-" + id + "-" + style;
    }

    private static Typeface getSystemFontFamily(String familyName) {
        if (familyName == null || familyName.isEmpty()) {
            return null;
        }
        Typeface typeface = Typeface.create(familyName, 0);
        Typeface defaultTypeface = Typeface.create(Typeface.DEFAULT, 0);
        if (typeface == null || typeface.equals(defaultTypeface)) {
            return null;
        }
        return typeface;
    }

    public static Typeface createFromResourcesFamilyXml(Context context, FontResourcesParserCompat.FamilyResourceEntry entry, Resources resources, int id, int style, ResourcesCompat.FontCallback fontCallback, Handler handler, boolean isRequestFromLayoutInflator) {
        Typeface typeface;
        boolean isBlocking;
        if (!(entry instanceof FontResourcesParserCompat.ProviderResourceEntry)) {
            typeface = sTypefaceCompatImpl.createFromFontFamilyFilesResourceEntry(context, (FontResourcesParserCompat.FontFamilyFilesResourceEntry) entry, resources, style);
            if (fontCallback != null) {
                if (typeface != null) {
                    fontCallback.callbackSuccessAsync(typeface, handler);
                } else {
                    fontCallback.callbackFailAsync(-3, handler);
                }
            }
        } else {
            FontResourcesParserCompat.ProviderResourceEntry providerEntry = (FontResourcesParserCompat.ProviderResourceEntry) entry;
            Typeface fontFamilyTypeface = getSystemFontFamily(providerEntry.getSystemFontFamilyName());
            if (fontFamilyTypeface != null) {
                if (fontCallback != null) {
                    fontCallback.callbackSuccessAsync(fontFamilyTypeface, handler);
                }
                return fontFamilyTypeface;
            }
            if (isRequestFromLayoutInflator) {
                isBlocking = providerEntry.getFetchStrategy() == 0;
            } else {
                isBlocking = fontCallback == null;
            }
            int timeout = isRequestFromLayoutInflator ? providerEntry.getTimeout() : -1;
            Handler newHandler = ResourcesCompat.FontCallback.getHandler(handler);
            ResourcesCallbackAdapter newCallback = new ResourcesCallbackAdapter(fontCallback);
            typeface = FontsContractCompat.requestFont(context, providerEntry.getRequest(), style, isBlocking, timeout, newHandler, newCallback);
        }
        if (typeface != null) {
            sTypefaceCache.put(createResourceUid(resources, id, style), typeface);
        }
        return typeface;
    }

    public static Typeface createFromResourcesFontFile(Context context, Resources resources, int id, String path, int style) {
        Typeface typeface = sTypefaceCompatImpl.createFromResourcesFontFile(context, resources, id, path, style);
        if (typeface != null) {
            String resourceUid = createResourceUid(resources, id, style);
            sTypefaceCache.put(resourceUid, typeface);
        }
        return typeface;
    }

    public static Typeface createFromFontInfo(Context context, CancellationSignal cancellationSignal, FontsContractCompat.FontInfo[] fonts, int style) {
        return sTypefaceCompatImpl.createFromFontInfo(context, cancellationSignal, fonts, style);
    }

    private static Typeface getBestFontFromFamily(Context context, Typeface typeface, int style) {
        TypefaceCompatBaseImpl typefaceCompatBaseImpl = sTypefaceCompatImpl;
        FontResourcesParserCompat.FontFamilyFilesResourceEntry families = typefaceCompatBaseImpl.getFontFamily(typeface);
        if (families == null) {
            return null;
        }
        return typefaceCompatBaseImpl.createFromFontFamilyFilesResourceEntry(context, families, context.getResources(), style);
    }

    public static Typeface create(Context context, Typeface family, int style) {
        Typeface typefaceFromFamily;
        if (context == null) {
            throw new IllegalArgumentException("Context cannot be null");
        }
        if (Build.VERSION.SDK_INT < 21 && (typefaceFromFamily = getBestFontFromFamily(context, family, style)) != null) {
            return typefaceFromFamily;
        }
        return Typeface.create(family, style);
    }

    public static void clearCache() {
        sTypefaceCache.evictAll();
    }

    /* loaded from: classes.dex */
    public static class ResourcesCallbackAdapter extends FontsContractCompat.FontRequestCallback {
        private ResourcesCompat.FontCallback mFontCallback;

        public ResourcesCallbackAdapter(ResourcesCompat.FontCallback fontCallback) {
            this.mFontCallback = fontCallback;
        }

        @Override // androidx.core.provider.FontsContractCompat.FontRequestCallback
        public void onTypefaceRetrieved(Typeface typeface) {
            ResourcesCompat.FontCallback fontCallback = this.mFontCallback;
            if (fontCallback != null) {
                fontCallback.onFontRetrieved(typeface);
            }
        }

        @Override // androidx.core.provider.FontsContractCompat.FontRequestCallback
        public void onTypefaceRequestFailed(int reason) {
            ResourcesCompat.FontCallback fontCallback = this.mFontCallback;
            if (fontCallback != null) {
                fontCallback.onFontRetrievalFailed(reason);
            }
        }
    }
}
