package androidx.appcompat.widget;

import android.content.res.AssetFileDescriptor;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.Movie;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import androidx.appcompat.resources.Compatibility;
import androidx.core.content.res.ResourcesCompat;
import java.io.IOException;
import java.io.InputStream;
import org.xmlpull.v1.XmlPullParserException;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ResourcesWrapper extends Resources {
    private final Resources mResources;

    public ResourcesWrapper(Resources resources) {
        super(resources.getAssets(), resources.getDisplayMetrics(), resources.getConfiguration());
        this.mResources = resources;
    }

    @Override // android.content.res.Resources
    public CharSequence getText(int id) throws Resources.NotFoundException {
        return this.mResources.getText(id);
    }

    @Override // android.content.res.Resources
    public CharSequence getQuantityText(int id, int quantity) throws Resources.NotFoundException {
        return this.mResources.getQuantityText(id, quantity);
    }

    @Override // android.content.res.Resources
    public String getString(int id) throws Resources.NotFoundException {
        return this.mResources.getString(id);
    }

    @Override // android.content.res.Resources
    public String getString(int id, Object... formatArgs) throws Resources.NotFoundException {
        return this.mResources.getString(id, formatArgs);
    }

    @Override // android.content.res.Resources
    public String getQuantityString(int id, int quantity, Object... formatArgs) throws Resources.NotFoundException {
        return this.mResources.getQuantityString(id, quantity, formatArgs);
    }

    @Override // android.content.res.Resources
    public String getQuantityString(int id, int quantity) throws Resources.NotFoundException {
        return this.mResources.getQuantityString(id, quantity);
    }

    @Override // android.content.res.Resources
    public CharSequence getText(int id, CharSequence def) {
        return this.mResources.getText(id, def);
    }

    @Override // android.content.res.Resources
    public CharSequence[] getTextArray(int id) throws Resources.NotFoundException {
        return this.mResources.getTextArray(id);
    }

    @Override // android.content.res.Resources
    public String[] getStringArray(int id) throws Resources.NotFoundException {
        return this.mResources.getStringArray(id);
    }

    @Override // android.content.res.Resources
    public int[] getIntArray(int id) throws Resources.NotFoundException {
        return this.mResources.getIntArray(id);
    }

    @Override // android.content.res.Resources
    public TypedArray obtainTypedArray(int id) throws Resources.NotFoundException {
        return this.mResources.obtainTypedArray(id);
    }

    @Override // android.content.res.Resources
    public float getDimension(int id) throws Resources.NotFoundException {
        return this.mResources.getDimension(id);
    }

    @Override // android.content.res.Resources
    public int getDimensionPixelOffset(int id) throws Resources.NotFoundException {
        return this.mResources.getDimensionPixelOffset(id);
    }

    @Override // android.content.res.Resources
    public int getDimensionPixelSize(int id) throws Resources.NotFoundException {
        return this.mResources.getDimensionPixelSize(id);
    }

    @Override // android.content.res.Resources
    public float getFraction(int id, int base, int pbase) {
        return this.mResources.getFraction(id, base, pbase);
    }

    @Override // android.content.res.Resources
    public Drawable getDrawable(int id) throws Resources.NotFoundException {
        return this.mResources.getDrawable(id);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final Drawable getDrawableCanonical(int id) throws Resources.NotFoundException {
        return super.getDrawable(id);
    }

    @Override // android.content.res.Resources
    public Drawable getDrawable(int id, Resources.Theme theme) throws Resources.NotFoundException {
        return ResourcesCompat.getDrawable(this.mResources, id, theme);
    }

    @Override // android.content.res.Resources
    public Drawable getDrawableForDensity(int id, int density) throws Resources.NotFoundException {
        return ResourcesCompat.getDrawableForDensity(this.mResources, id, density, null);
    }

    @Override // android.content.res.Resources
    public Drawable getDrawableForDensity(int id, int density, Resources.Theme theme) {
        return ResourcesCompat.getDrawableForDensity(this.mResources, id, density, theme);
    }

    @Override // android.content.res.Resources
    public Movie getMovie(int id) throws Resources.NotFoundException {
        return this.mResources.getMovie(id);
    }

    @Override // android.content.res.Resources
    public int getColor(int id) throws Resources.NotFoundException {
        return this.mResources.getColor(id);
    }

    @Override // android.content.res.Resources
    public ColorStateList getColorStateList(int id) throws Resources.NotFoundException {
        return this.mResources.getColorStateList(id);
    }

    @Override // android.content.res.Resources
    public boolean getBoolean(int id) throws Resources.NotFoundException {
        return this.mResources.getBoolean(id);
    }

    @Override // android.content.res.Resources
    public int getInteger(int id) throws Resources.NotFoundException {
        return this.mResources.getInteger(id);
    }

    @Override // android.content.res.Resources
    public XmlResourceParser getLayout(int id) throws Resources.NotFoundException {
        return this.mResources.getLayout(id);
    }

    @Override // android.content.res.Resources
    public XmlResourceParser getAnimation(int id) throws Resources.NotFoundException {
        return this.mResources.getAnimation(id);
    }

    @Override // android.content.res.Resources
    public XmlResourceParser getXml(int id) throws Resources.NotFoundException {
        return this.mResources.getXml(id);
    }

    @Override // android.content.res.Resources
    public InputStream openRawResource(int id) throws Resources.NotFoundException {
        return this.mResources.openRawResource(id);
    }

    @Override // android.content.res.Resources
    public InputStream openRawResource(int id, TypedValue value) throws Resources.NotFoundException {
        return this.mResources.openRawResource(id, value);
    }

    @Override // android.content.res.Resources
    public AssetFileDescriptor openRawResourceFd(int id) throws Resources.NotFoundException {
        return this.mResources.openRawResourceFd(id);
    }

    @Override // android.content.res.Resources
    public void getValue(int id, TypedValue outValue, boolean resolveRefs) throws Resources.NotFoundException {
        this.mResources.getValue(id, outValue, resolveRefs);
    }

    @Override // android.content.res.Resources
    public void getValueForDensity(int id, int density, TypedValue outValue, boolean resolveRefs) throws Resources.NotFoundException {
        Compatibility.Api15Impl.getValueForDensity(this.mResources, id, density, outValue, resolveRefs);
    }

    @Override // android.content.res.Resources
    public void getValue(String name, TypedValue outValue, boolean resolveRefs) throws Resources.NotFoundException {
        this.mResources.getValue(name, outValue, resolveRefs);
    }

    @Override // android.content.res.Resources
    public TypedArray obtainAttributes(AttributeSet set, int[] attrs) {
        return this.mResources.obtainAttributes(set, attrs);
    }

    @Override // android.content.res.Resources
    public void updateConfiguration(Configuration config, DisplayMetrics metrics) {
        super.updateConfiguration(config, metrics);
        Resources resources = this.mResources;
        if (resources != null) {
            resources.updateConfiguration(config, metrics);
        }
    }

    @Override // android.content.res.Resources
    public DisplayMetrics getDisplayMetrics() {
        return this.mResources.getDisplayMetrics();
    }

    @Override // android.content.res.Resources
    public Configuration getConfiguration() {
        return this.mResources.getConfiguration();
    }

    @Override // android.content.res.Resources
    public int getIdentifier(String name, String defType, String defPackage) {
        return this.mResources.getIdentifier(name, defType, defPackage);
    }

    @Override // android.content.res.Resources
    public String getResourceName(int resid) throws Resources.NotFoundException {
        return this.mResources.getResourceName(resid);
    }

    @Override // android.content.res.Resources
    public String getResourcePackageName(int resid) throws Resources.NotFoundException {
        return this.mResources.getResourcePackageName(resid);
    }

    @Override // android.content.res.Resources
    public String getResourceTypeName(int resid) throws Resources.NotFoundException {
        return this.mResources.getResourceTypeName(resid);
    }

    @Override // android.content.res.Resources
    public String getResourceEntryName(int resid) throws Resources.NotFoundException {
        return this.mResources.getResourceEntryName(resid);
    }

    @Override // android.content.res.Resources
    public void parseBundleExtras(XmlResourceParser parser, Bundle outBundle) throws XmlPullParserException, IOException {
        this.mResources.parseBundleExtras(parser, outBundle);
    }

    @Override // android.content.res.Resources
    public void parseBundleExtra(String tagName, AttributeSet attrs, Bundle outBundle) throws XmlPullParserException {
        this.mResources.parseBundleExtra(tagName, attrs, outBundle);
    }
}
