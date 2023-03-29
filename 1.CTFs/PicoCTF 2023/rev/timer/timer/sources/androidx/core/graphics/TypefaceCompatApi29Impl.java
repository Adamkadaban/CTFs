package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.graphics.fonts.Font;
import android.graphics.fonts.FontFamily;
import android.graphics.fonts.FontStyle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.content.res.FontResourcesParserCompat;
import androidx.core.provider.FontsContractCompat;
import java.io.IOException;
import java.io.InputStream;
/* loaded from: classes.dex */
public class TypefaceCompatApi29Impl extends TypefaceCompatBaseImpl {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.core.graphics.TypefaceCompatBaseImpl
    public FontsContractCompat.FontInfo findBestInfo(FontsContractCompat.FontInfo[] fonts, int style) {
        throw new RuntimeException("Do not use this function in API 29 or later.");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.core.graphics.TypefaceCompatBaseImpl
    public Typeface createFromInputStream(Context context, InputStream is) {
        throw new RuntimeException("Do not use this function in API 29 or later.");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0067, code lost:
        if (r0 != null) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0069, code lost:
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x006e, code lost:
        if ((r15 & 1) == 0) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0070, code lost:
        r5 = androidx.constraintlayout.core.motion.utils.TypedValues.TransitionType.TYPE_DURATION;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0073, code lost:
        r5 = 400;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0077, code lost:
        if ((r15 & 2) == 0) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0079, code lost:
        r4 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x007c, code lost:
        r3 = new android.graphics.fonts.FontStyle(r5, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0090, code lost:
        return new android.graphics.Typeface.CustomFallbackBuilder(r0.build()).setStyle(r3).build();
     */
    @Override // androidx.core.graphics.TypefaceCompatBaseImpl
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.graphics.Typeface createFromFontInfo(android.content.Context r12, android.os.CancellationSignal r13, androidx.core.provider.FontsContractCompat.FontInfo[] r14, int r15) {
        /*
            r11 = this;
            r0 = 0
            android.content.ContentResolver r1 = r12.getContentResolver()
            r2 = 0
            int r3 = r14.length     // Catch: java.lang.Exception -> L91
            r4 = 0
            r5 = 0
        L9:
            r6 = 1
            if (r5 >= r3) goto L67
            r7 = r14[r5]     // Catch: java.lang.Exception -> L91
            android.net.Uri r8 = r7.getUri()     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
            java.lang.String r9 = "r"
            android.os.ParcelFileDescriptor r8 = r1.openFileDescriptor(r8, r9, r13)     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
            if (r8 != 0) goto L20
            if (r8 == 0) goto L1f
            r8.close()     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
        L1f:
            goto L64
        L20:
            android.graphics.fonts.Font$Builder r9 = new android.graphics.fonts.Font$Builder     // Catch: java.lang.Throwable -> L57
            r9.<init>(r8)     // Catch: java.lang.Throwable -> L57
            int r10 = r7.getWeight()     // Catch: java.lang.Throwable -> L57
            android.graphics.fonts.Font$Builder r9 = r9.setWeight(r10)     // Catch: java.lang.Throwable -> L57
            boolean r10 = r7.isItalic()     // Catch: java.lang.Throwable -> L57
            if (r10 == 0) goto L34
            goto L35
        L34:
            r6 = 0
        L35:
            android.graphics.fonts.Font$Builder r6 = r9.setSlant(r6)     // Catch: java.lang.Throwable -> L57
            int r9 = r7.getTtcIndex()     // Catch: java.lang.Throwable -> L57
            android.graphics.fonts.Font$Builder r6 = r6.setTtcIndex(r9)     // Catch: java.lang.Throwable -> L57
            android.graphics.fonts.Font r6 = r6.build()     // Catch: java.lang.Throwable -> L57
            if (r0 != 0) goto L4e
            android.graphics.fonts.FontFamily$Builder r9 = new android.graphics.fonts.FontFamily$Builder     // Catch: java.lang.Throwable -> L57
            r9.<init>(r6)     // Catch: java.lang.Throwable -> L57
            r0 = r9
            goto L51
        L4e:
            r0.addFont(r6)     // Catch: java.lang.Throwable -> L57
        L51:
            if (r8 == 0) goto L56
            r8.close()     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
        L56:
            goto L64
        L57:
            r6 = move-exception
            if (r8 == 0) goto L62
            r8.close()     // Catch: java.lang.Throwable -> L5e
            goto L62
        L5e:
            r9 = move-exception
            r6.addSuppressed(r9)     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
        L62:
            throw r6     // Catch: java.io.IOException -> L63 java.lang.Exception -> L91
        L63:
            r6 = move-exception
        L64:
            int r5 = r5 + 1
            goto L9
        L67:
            if (r0 != 0) goto L6a
            return r2
        L6a:
            android.graphics.fonts.FontStyle r3 = new android.graphics.fonts.FontStyle     // Catch: java.lang.Exception -> L91
            r5 = r15 & 1
            if (r5 == 0) goto L73
            r5 = 700(0x2bc, float:9.81E-43)
            goto L75
        L73:
            r5 = 400(0x190, float:5.6E-43)
        L75:
            r7 = r15 & 2
            if (r7 == 0) goto L7b
            r4 = 1
            goto L7c
        L7b:
        L7c:
            r3.<init>(r5, r4)     // Catch: java.lang.Exception -> L91
            android.graphics.Typeface$CustomFallbackBuilder r4 = new android.graphics.Typeface$CustomFallbackBuilder     // Catch: java.lang.Exception -> L91
            android.graphics.fonts.FontFamily r5 = r0.build()     // Catch: java.lang.Exception -> L91
            r4.<init>(r5)     // Catch: java.lang.Exception -> L91
            android.graphics.Typeface$CustomFallbackBuilder r4 = r4.setStyle(r3)     // Catch: java.lang.Exception -> L91
            android.graphics.Typeface r2 = r4.build()     // Catch: java.lang.Exception -> L91
            return r2
        L91:
            r3 = move-exception
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.TypefaceCompatApi29Impl.createFromFontInfo(android.content.Context, android.os.CancellationSignal, androidx.core.provider.FontsContractCompat$FontInfo[], int):android.graphics.Typeface");
    }

    @Override // androidx.core.graphics.TypefaceCompatBaseImpl
    public Typeface createFromFontFamilyFilesResourceEntry(Context context, FontResourcesParserCompat.FontFamilyFilesResourceEntry familyEntry, Resources resources, int style) {
        FontFamily.Builder familyBuilder = null;
        try {
            FontResourcesParserCompat.FontFileResourceEntry[] entries = familyEntry.getEntries();
            int length = entries.length;
            int i = 0;
            while (true) {
                int i2 = 1;
                if (i >= length) {
                    break;
                }
                FontResourcesParserCompat.FontFileResourceEntry entry = entries[i];
                try {
                    Font.Builder weight = new Font.Builder(resources, entry.getResourceId()).setWeight(entry.getWeight());
                    if (!entry.isItalic()) {
                        i2 = 0;
                    }
                    Font platformFont = weight.setSlant(i2).setTtcIndex(entry.getTtcIndex()).setFontVariationSettings(entry.getVariationSettings()).build();
                    if (familyBuilder == null) {
                        familyBuilder = new FontFamily.Builder(platformFont);
                    } else {
                        familyBuilder.addFont(platformFont);
                    }
                } catch (IOException e) {
                }
                i++;
            }
            if (familyBuilder == null) {
                return null;
            }
            FontStyle defaultStyle = new FontStyle((style & 1) != 0 ? TypedValues.TransitionType.TYPE_DURATION : 400, (style & 2) != 0 ? 1 : 0);
            return new Typeface.CustomFallbackBuilder(familyBuilder.build()).setStyle(defaultStyle).build();
        } catch (Exception e2) {
            return null;
        }
    }

    @Override // androidx.core.graphics.TypefaceCompatBaseImpl
    public Typeface createFromResourcesFontFile(Context context, Resources resources, int id, String path, int style) {
        try {
            Font font = new Font.Builder(resources, id).build();
            FontFamily family = new FontFamily.Builder(font).build();
            return new Typeface.CustomFallbackBuilder(family).setStyle(font.getStyle()).build();
        } catch (Exception e) {
            return null;
        }
    }
}
