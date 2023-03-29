package androidx.core.graphics;

import android.graphics.Color;
import android.graphics.ColorSpace;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: Color.kt */
@Metadata(d1 = {"\u0000>\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\u0010\t\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\u001a\r\u0010\u0018\u001a\u00020\u0004*\u00020\u0019H\u0087\n\u001a\r\u0010\u0018\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\r\u0010\u0018\u001a\u00020\u0004*\u00020\u0005H\u0087\n\u001a\r\u0010\u001a\u001a\u00020\u0004*\u00020\u0019H\u0087\n\u001a\r\u0010\u001a\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\r\u0010\u001a\u001a\u00020\u0004*\u00020\u0005H\u0087\n\u001a\r\u0010\u001b\u001a\u00020\u0004*\u00020\u0019H\u0087\n\u001a\r\u0010\u001b\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\r\u0010\u001b\u001a\u00020\u0004*\u00020\u0005H\u0087\n\u001a\r\u0010\u001c\u001a\u00020\u0004*\u00020\u0019H\u0087\n\u001a\r\u0010\u001c\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\r\u0010\u001c\u001a\u00020\u0004*\u00020\u0005H\u0087\n\u001a\u0015\u0010\u001d\u001a\u00020\u0019*\u00020\u00192\u0006\u0010\t\u001a\u00020\nH\u0087\f\u001a\u0015\u0010\u001d\u001a\u00020\u0019*\u00020\u00192\u0006\u0010\t\u001a\u00020\u001eH\u0087\f\u001a\u0015\u0010\u001d\u001a\u00020\u0005*\u00020\u00012\u0006\u0010\t\u001a\u00020\nH\u0087\f\u001a\u0015\u0010\u001d\u001a\u00020\u0005*\u00020\u00012\u0006\u0010\t\u001a\u00020\u001eH\u0087\f\u001a\u0015\u0010\u001d\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\t\u001a\u00020\nH\u0087\f\u001a\u0015\u0010\u001d\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\t\u001a\u00020\u001eH\u0087\f\u001a\u0015\u0010\u001f\u001a\u00020\u0019*\u00020\u00192\u0006\u0010 \u001a\u00020\u0019H\u0087\u0002\u001a\r\u0010!\u001a\u00020\u0019*\u00020\u0001H\u0087\b\u001a\r\u0010!\u001a\u00020\u0019*\u00020\u0005H\u0087\b\u001a\r\u0010\"\u001a\u00020\u0001*\u00020\u0005H\u0087\b\u001a\r\u0010\"\u001a\u00020\u0001*\u00020#H\u0087\b\u001a\r\u0010$\u001a\u00020\u0005*\u00020\u0001H\u0087\b\"\u0016\u0010\u0000\u001a\u00020\u0001*\u00020\u00018Æ\u0002¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003\"\u0016\u0010\u0000\u001a\u00020\u0004*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0006\"\u0016\u0010\u0007\u001a\u00020\u0001*\u00020\u00018Æ\u0002¢\u0006\u0006\u001a\u0004\b\b\u0010\u0003\"\u0016\u0010\u0007\u001a\u00020\u0004*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\b\u0010\u0006\"\u0016\u0010\t\u001a\u00020\n*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u000b\u0010\f\"\u0016\u0010\r\u001a\u00020\u0001*\u00020\u00018Æ\u0002¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u0003\"\u0016\u0010\r\u001a\u00020\u0004*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u0006\"\u0016\u0010\u000f\u001a\u00020\u0010*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u000f\u0010\u0011\"\u0016\u0010\u0012\u001a\u00020\u0010*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u0011\"\u0016\u0010\u0013\u001a\u00020\u0004*\u00020\u00018Ç\u0002¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0015\"\u0016\u0010\u0013\u001a\u00020\u0004*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0006\"\u0016\u0010\u0016\u001a\u00020\u0001*\u00020\u00018Æ\u0002¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0003\"\u0016\u0010\u0016\u001a\u00020\u0004*\u00020\u00058Ç\u0002¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0006¨\u0006%"}, d2 = {"alpha", "", "getAlpha", "(I)I", "", "", "(J)F", "blue", "getBlue", "colorSpace", "Landroid/graphics/ColorSpace;", "getColorSpace", "(J)Landroid/graphics/ColorSpace;", "green", "getGreen", "isSrgb", "", "(J)Z", "isWideGamut", "luminance", "getLuminance", "(I)F", "red", "getRed", "component1", "Landroid/graphics/Color;", "component2", "component3", "component4", "convertTo", "Landroid/graphics/ColorSpace$Named;", "plus", "c", "toColor", "toColorInt", "", "toColorLong", "core-ktx_release"}, k = 2, mv = {1, 5, 1}, xi = 48)
/* loaded from: classes.dex */
public final class ColorKt {
    public static final float component1(Color $this$component1) {
        Intrinsics.checkNotNullParameter($this$component1, "<this>");
        return $this$component1.getComponent(0);
    }

    public static final float component2(Color $this$component2) {
        Intrinsics.checkNotNullParameter($this$component2, "<this>");
        return $this$component2.getComponent(1);
    }

    public static final float component3(Color $this$component3) {
        Intrinsics.checkNotNullParameter($this$component3, "<this>");
        return $this$component3.getComponent(2);
    }

    public static final float component4(Color $this$component4) {
        Intrinsics.checkNotNullParameter($this$component4, "<this>");
        return $this$component4.getComponent(3);
    }

    public static final Color plus(Color $this$plus, Color c) {
        Intrinsics.checkNotNullParameter($this$plus, "<this>");
        Intrinsics.checkNotNullParameter(c, "c");
        Color compositeColors = ColorUtils.compositeColors(c, $this$plus);
        Intrinsics.checkNotNullExpressionValue(compositeColors, "compositeColors(c, this)");
        return compositeColors;
    }

    public static final int getAlpha(int $this$alpha) {
        return ($this$alpha >> 24) & 255;
    }

    public static final int getRed(int $this$red) {
        return ($this$red >> 16) & 255;
    }

    public static final int getGreen(int $this$green) {
        return ($this$green >> 8) & 255;
    }

    public static final int getBlue(int $this$blue) {
        return $this$blue & 255;
    }

    public static final int component1(int $this$component1) {
        return ($this$component1 >> 24) & 255;
    }

    public static final int component2(int $this$component2) {
        return ($this$component2 >> 16) & 255;
    }

    public static final int component3(int $this$component3) {
        return ($this$component3 >> 8) & 255;
    }

    public static final int component4(int $this$component4) {
        return $this$component4 & 255;
    }

    public static final float getLuminance(int $this$luminance) {
        return Color.luminance($this$luminance);
    }

    public static final Color toColor(int $this$toColor) {
        Color valueOf = Color.valueOf($this$toColor);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static final long toColorLong(int $this$toColorLong) {
        return Color.pack($this$toColorLong);
    }

    public static final float component1(long $this$component1) {
        return Color.red($this$component1);
    }

    public static final float component2(long $this$component2) {
        return Color.green($this$component2);
    }

    public static final float component3(long $this$component3) {
        return Color.blue($this$component3);
    }

    public static final float component4(long $this$component4) {
        return Color.alpha($this$component4);
    }

    public static final float getAlpha(long $this$alpha) {
        return Color.alpha($this$alpha);
    }

    public static final float getRed(long $this$red) {
        return Color.red($this$red);
    }

    public static final float getGreen(long $this$green) {
        return Color.green($this$green);
    }

    public static final float getBlue(long $this$blue) {
        return Color.blue($this$blue);
    }

    public static final float getLuminance(long $this$luminance) {
        return Color.luminance($this$luminance);
    }

    public static final Color toColor(long $this$toColor) {
        Color valueOf = Color.valueOf($this$toColor);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static final int toColorInt(long $this$toColorInt) {
        return Color.toArgb($this$toColorInt);
    }

    public static final boolean isSrgb(long $this$isSrgb) {
        return Color.isSrgb($this$isSrgb);
    }

    public static final boolean isWideGamut(long $this$isWideGamut) {
        return Color.isWideGamut($this$isWideGamut);
    }

    public static final ColorSpace getColorSpace(long $this$colorSpace) {
        ColorSpace colorSpace = Color.colorSpace($this$colorSpace);
        Intrinsics.checkNotNullExpressionValue(colorSpace, "colorSpace(this)");
        return colorSpace;
    }

    public static final long convertTo(int $this$convertTo, ColorSpace.Named colorSpace) {
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        return Color.convert($this$convertTo, ColorSpace.get(colorSpace));
    }

    public static final long convertTo(int $this$convertTo, ColorSpace colorSpace) {
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        return Color.convert($this$convertTo, colorSpace);
    }

    public static final long convertTo(long $this$convertTo, ColorSpace.Named colorSpace) {
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        return Color.convert($this$convertTo, ColorSpace.get(colorSpace));
    }

    public static final long convertTo(long $this$convertTo, ColorSpace colorSpace) {
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        return Color.convert($this$convertTo, colorSpace);
    }

    public static final Color convertTo(Color $this$convertTo, ColorSpace.Named colorSpace) {
        Intrinsics.checkNotNullParameter($this$convertTo, "<this>");
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        Color convert = $this$convertTo.convert(ColorSpace.get(colorSpace));
        Intrinsics.checkNotNullExpressionValue(convert, "convert(ColorSpace.get(colorSpace))");
        return convert;
    }

    public static final Color convertTo(Color $this$convertTo, ColorSpace colorSpace) {
        Intrinsics.checkNotNullParameter($this$convertTo, "<this>");
        Intrinsics.checkNotNullParameter(colorSpace, "colorSpace");
        Color convert = $this$convertTo.convert(colorSpace);
        Intrinsics.checkNotNullExpressionValue(convert, "convert(colorSpace)");
        return convert;
    }

    public static final int toColorInt(String $this$toColorInt) {
        Intrinsics.checkNotNullParameter($this$toColorInt, "<this>");
        return Color.parseColor($this$toColorInt);
    }
}
