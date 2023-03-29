package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.AttributeSet;
import android.util.TypedValue;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.res.ResourcesCompat;
/* loaded from: classes.dex */
public class TintTypedArray {
    private final Context mContext;
    private TypedValue mTypedValue;
    private final TypedArray mWrapped;

    public static TintTypedArray obtainStyledAttributes(Context context, AttributeSet set, int[] attrs) {
        return new TintTypedArray(context, context.obtainStyledAttributes(set, attrs));
    }

    public static TintTypedArray obtainStyledAttributes(Context context, AttributeSet set, int[] attrs, int defStyleAttr, int defStyleRes) {
        return new TintTypedArray(context, context.obtainStyledAttributes(set, attrs, defStyleAttr, defStyleRes));
    }

    public static TintTypedArray obtainStyledAttributes(Context context, int resid, int[] attrs) {
        return new TintTypedArray(context, context.obtainStyledAttributes(resid, attrs));
    }

    private TintTypedArray(Context context, TypedArray array) {
        this.mContext = context;
        this.mWrapped = array;
    }

    public TypedArray getWrappedTypeArray() {
        return this.mWrapped;
    }

    public Drawable getDrawable(int index) {
        int resourceId;
        if (this.mWrapped.hasValue(index) && (resourceId = this.mWrapped.getResourceId(index, 0)) != 0) {
            return AppCompatResources.getDrawable(this.mContext, resourceId);
        }
        return this.mWrapped.getDrawable(index);
    }

    public Drawable getDrawableIfKnown(int index) {
        int resourceId;
        if (this.mWrapped.hasValue(index) && (resourceId = this.mWrapped.getResourceId(index, 0)) != 0) {
            return AppCompatDrawableManager.get().getDrawable(this.mContext, resourceId, true);
        }
        return null;
    }

    public Typeface getFont(int index, int style, ResourcesCompat.FontCallback fontCallback) {
        int resourceId = this.mWrapped.getResourceId(index, 0);
        if (resourceId == 0) {
            return null;
        }
        if (this.mTypedValue == null) {
            this.mTypedValue = new TypedValue();
        }
        return ResourcesCompat.getFont(this.mContext, resourceId, this.mTypedValue, style, fontCallback);
    }

    public int length() {
        return this.mWrapped.length();
    }

    public int getIndexCount() {
        return this.mWrapped.getIndexCount();
    }

    public int getIndex(int at) {
        return this.mWrapped.getIndex(at);
    }

    public Resources getResources() {
        return this.mWrapped.getResources();
    }

    public CharSequence getText(int index) {
        return this.mWrapped.getText(index);
    }

    public String getString(int index) {
        return this.mWrapped.getString(index);
    }

    public String getNonResourceString(int index) {
        return this.mWrapped.getNonResourceString(index);
    }

    public boolean getBoolean(int index, boolean defValue) {
        return this.mWrapped.getBoolean(index, defValue);
    }

    public int getInt(int index, int defValue) {
        return this.mWrapped.getInt(index, defValue);
    }

    public float getFloat(int index, float defValue) {
        return this.mWrapped.getFloat(index, defValue);
    }

    public int getColor(int index, int defValue) {
        return this.mWrapped.getColor(index, defValue);
    }

    public ColorStateList getColorStateList(int index) {
        int resourceId;
        ColorStateList value;
        if (this.mWrapped.hasValue(index) && (resourceId = this.mWrapped.getResourceId(index, 0)) != 0 && (value = AppCompatResources.getColorStateList(this.mContext, resourceId)) != null) {
            return value;
        }
        return this.mWrapped.getColorStateList(index);
    }

    public int getInteger(int index, int defValue) {
        return this.mWrapped.getInteger(index, defValue);
    }

    public float getDimension(int index, float defValue) {
        return this.mWrapped.getDimension(index, defValue);
    }

    public int getDimensionPixelOffset(int index, int defValue) {
        return this.mWrapped.getDimensionPixelOffset(index, defValue);
    }

    public int getDimensionPixelSize(int index, int defValue) {
        return this.mWrapped.getDimensionPixelSize(index, defValue);
    }

    public int getLayoutDimension(int index, String name) {
        return this.mWrapped.getLayoutDimension(index, name);
    }

    public int getLayoutDimension(int index, int defValue) {
        return this.mWrapped.getLayoutDimension(index, defValue);
    }

    public float getFraction(int index, int base, int pbase, float defValue) {
        return this.mWrapped.getFraction(index, base, pbase, defValue);
    }

    public int getResourceId(int index, int defValue) {
        return this.mWrapped.getResourceId(index, defValue);
    }

    public CharSequence[] getTextArray(int index) {
        return this.mWrapped.getTextArray(index);
    }

    public boolean getValue(int index, TypedValue outValue) {
        return this.mWrapped.getValue(index, outValue);
    }

    public int getType(int index) {
        if (Build.VERSION.SDK_INT >= 21) {
            return this.mWrapped.getType(index);
        }
        if (this.mTypedValue == null) {
            this.mTypedValue = new TypedValue();
        }
        this.mWrapped.getValue(index, this.mTypedValue);
        return this.mTypedValue.type;
    }

    public boolean hasValue(int index) {
        return this.mWrapped.hasValue(index);
    }

    public TypedValue peekValue(int index) {
        return this.mWrapped.peekValue(index);
    }

    public String getPositionDescription() {
        return this.mWrapped.getPositionDescription();
    }

    public void recycle() {
        this.mWrapped.recycle();
    }

    public int getChangingConfigurations() {
        return this.mWrapped.getChangingConfigurations();
    }
}
