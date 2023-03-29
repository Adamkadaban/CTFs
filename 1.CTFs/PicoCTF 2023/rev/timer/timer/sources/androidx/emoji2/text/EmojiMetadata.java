package androidx.emoji2.text;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import androidx.emoji2.text.flatbuffer.MetadataItem;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
/* loaded from: classes.dex */
public class EmojiMetadata {
    public static final int HAS_GLYPH_ABSENT = 1;
    public static final int HAS_GLYPH_EXISTS = 2;
    public static final int HAS_GLYPH_UNKNOWN = 0;
    private static final ThreadLocal<MetadataItem> sMetadataItem = new ThreadLocal<>();
    private volatile int mHasGlyph = 0;
    private final int mIndex;
    private final MetadataRepo mMetadataRepo;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface HasGlyph {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EmojiMetadata(MetadataRepo metadataRepo, int index) {
        this.mMetadataRepo = metadataRepo;
        this.mIndex = index;
    }

    public void draw(Canvas canvas, float x, float y, Paint paint) {
        Typeface typeface = this.mMetadataRepo.getTypeface();
        Typeface oldTypeface = paint.getTypeface();
        paint.setTypeface(typeface);
        int charArrayStartIndex = this.mIndex * 2;
        canvas.drawText(this.mMetadataRepo.getEmojiCharArray(), charArrayStartIndex, 2, x, y, paint);
        paint.setTypeface(oldTypeface);
    }

    public Typeface getTypeface() {
        return this.mMetadataRepo.getTypeface();
    }

    private MetadataItem getMetadataItem() {
        ThreadLocal<MetadataItem> threadLocal = sMetadataItem;
        MetadataItem result = threadLocal.get();
        if (result == null) {
            result = new MetadataItem();
            threadLocal.set(result);
        }
        this.mMetadataRepo.getMetadataList().list(result, this.mIndex);
        return result;
    }

    public int getId() {
        return getMetadataItem().id();
    }

    public short getWidth() {
        return getMetadataItem().width();
    }

    public short getHeight() {
        return getMetadataItem().height();
    }

    public short getCompatAdded() {
        return getMetadataItem().compatAdded();
    }

    public short getSdkAdded() {
        return getMetadataItem().sdkAdded();
    }

    public int getHasGlyph() {
        return this.mHasGlyph;
    }

    public void resetHasGlyphCache() {
        this.mHasGlyph = 0;
    }

    public void setHasGlyph(boolean hasGlyph) {
        this.mHasGlyph = hasGlyph ? 2 : 1;
    }

    public boolean isDefaultEmoji() {
        return getMetadataItem().emojiStyle();
    }

    public int getCodepointAt(int index) {
        return getMetadataItem().codepoints(index);
    }

    public int getCodepointsLength() {
        return getMetadataItem().codepointsLength();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(super.toString());
        builder.append(", id:");
        builder.append(Integer.toHexString(getId()));
        builder.append(", codepoints:");
        int codepointsLength = getCodepointsLength();
        for (int i = 0; i < codepointsLength; i++) {
            builder.append(Integer.toHexString(getCodepointAt(i)));
            builder.append(" ");
        }
        return builder.toString();
    }
}
