package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.LocaleList;
import android.text.method.PasswordTransformationMethod;
import android.util.AttributeSet;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.TextView;
import androidx.appcompat.R;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.inputmethod.EditorInfoCompat;
import androidx.core.widget.AutoSizeableTextView;
import androidx.core.widget.TextViewCompat;
import java.lang.ref.WeakReference;
import java.util.Locale;
/* loaded from: classes.dex */
class AppCompatTextHelper {
    private static final int MONOSPACE = 3;
    private static final int SANS = 1;
    private static final int SERIF = 2;
    private static final int TEXT_FONT_WEIGHT_UNSPECIFIED = -1;
    private boolean mAsyncFontPending;
    private final AppCompatTextViewAutoSizeHelper mAutoSizeTextHelper;
    private TintInfo mDrawableBottomTint;
    private TintInfo mDrawableEndTint;
    private TintInfo mDrawableLeftTint;
    private TintInfo mDrawableRightTint;
    private TintInfo mDrawableStartTint;
    private TintInfo mDrawableTint;
    private TintInfo mDrawableTopTint;
    private Typeface mFontTypeface;
    private final TextView mView;
    private int mStyle = 0;
    private int mFontWeight = -1;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppCompatTextHelper(TextView view) {
        this.mView = view;
        this.mAutoSizeTextHelper = new AppCompatTextViewAutoSizeHelper(view);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        boolean allCaps;
        boolean allCapsSet;
        ColorStateList textColorLink;
        ColorStateList textColor;
        String localeListString;
        String fontVariation;
        AppCompatDrawableManager drawableManager;
        String localeListString2;
        AppCompatDrawableManager drawableManager2;
        Drawable drawableBottom;
        Context context = this.mView.getContext();
        AppCompatDrawableManager drawableManager3 = AppCompatDrawableManager.get();
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, attrs, R.styleable.AppCompatTextHelper, defStyleAttr, 0);
        TextView textView = this.mView;
        ViewCompat.saveAttributeDataForStyleable(textView, textView.getContext(), R.styleable.AppCompatTextHelper, attrs, a.getWrappedTypeArray(), defStyleAttr, 0);
        int ap = a.getResourceId(R.styleable.AppCompatTextHelper_android_textAppearance, -1);
        if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableLeft)) {
            this.mDrawableLeftTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableLeft, 0));
        }
        if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableTop)) {
            this.mDrawableTopTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableTop, 0));
        }
        if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableRight)) {
            this.mDrawableRightTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableRight, 0));
        }
        if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableBottom)) {
            this.mDrawableBottomTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableBottom, 0));
        }
        if (Build.VERSION.SDK_INT >= 17) {
            if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableStart)) {
                this.mDrawableStartTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableStart, 0));
            }
            if (a.hasValue(R.styleable.AppCompatTextHelper_android_drawableEnd)) {
                this.mDrawableEndTint = createTintInfo(context, drawableManager3, a.getResourceId(R.styleable.AppCompatTextHelper_android_drawableEnd, 0));
            }
        }
        a.recycle();
        boolean hasPwdTm = this.mView.getTransformationMethod() instanceof PasswordTransformationMethod;
        boolean allCaps2 = false;
        boolean allCapsSet2 = false;
        ColorStateList textColor2 = null;
        ColorStateList textColorHint = null;
        ColorStateList textColorLink2 = null;
        String fontVariation2 = null;
        String localeListString3 = null;
        if (ap != -1) {
            TintTypedArray a2 = TintTypedArray.obtainStyledAttributes(context, ap, R.styleable.TextAppearance);
            if (!hasPwdTm && a2.hasValue(R.styleable.TextAppearance_textAllCaps)) {
                allCapsSet2 = true;
                allCaps2 = a2.getBoolean(R.styleable.TextAppearance_textAllCaps, false);
            }
            updateTypefaceAndStyle(context, a2);
            if (Build.VERSION.SDK_INT < 23) {
                if (a2.hasValue(R.styleable.TextAppearance_android_textColor)) {
                    textColor2 = a2.getColorStateList(R.styleable.TextAppearance_android_textColor);
                }
                if (a2.hasValue(R.styleable.TextAppearance_android_textColorHint)) {
                    textColorHint = a2.getColorStateList(R.styleable.TextAppearance_android_textColorHint);
                }
                if (a2.hasValue(R.styleable.TextAppearance_android_textColorLink)) {
                    textColorLink2 = a2.getColorStateList(R.styleable.TextAppearance_android_textColorLink);
                }
            }
            if (a2.hasValue(R.styleable.TextAppearance_textLocale)) {
                localeListString3 = a2.getString(R.styleable.TextAppearance_textLocale);
            }
            if (Build.VERSION.SDK_INT >= 26 && a2.hasValue(R.styleable.TextAppearance_fontVariationSettings)) {
                fontVariation2 = a2.getString(R.styleable.TextAppearance_fontVariationSettings);
            }
            a2.recycle();
        }
        TintTypedArray a3 = TintTypedArray.obtainStyledAttributes(context, attrs, R.styleable.TextAppearance, defStyleAttr, 0);
        if (!hasPwdTm && a3.hasValue(R.styleable.TextAppearance_textAllCaps)) {
            allCaps = a3.getBoolean(R.styleable.TextAppearance_textAllCaps, false);
            allCapsSet = true;
        } else {
            allCaps = allCaps2;
            allCapsSet = allCapsSet2;
        }
        if (Build.VERSION.SDK_INT >= 23) {
            ColorStateList colorStateList = textColorLink2;
            textColorLink = textColor2;
            textColor = colorStateList;
        } else {
            if (a3.hasValue(R.styleable.TextAppearance_android_textColor)) {
                textColor2 = a3.getColorStateList(R.styleable.TextAppearance_android_textColor);
            }
            if (a3.hasValue(R.styleable.TextAppearance_android_textColorHint)) {
                textColorHint = a3.getColorStateList(R.styleable.TextAppearance_android_textColorHint);
            }
            if (!a3.hasValue(R.styleable.TextAppearance_android_textColorLink)) {
                ColorStateList colorStateList2 = textColorLink2;
                textColorLink = textColor2;
                textColor = colorStateList2;
            } else {
                textColorLink = textColor2;
                textColor = a3.getColorStateList(R.styleable.TextAppearance_android_textColorLink);
            }
        }
        if (!a3.hasValue(R.styleable.TextAppearance_textLocale)) {
            localeListString = localeListString3;
        } else {
            localeListString = a3.getString(R.styleable.TextAppearance_textLocale);
        }
        String fontVariation3 = fontVariation2;
        if (Build.VERSION.SDK_INT >= 26 && a3.hasValue(R.styleable.TextAppearance_fontVariationSettings)) {
            fontVariation = a3.getString(R.styleable.TextAppearance_fontVariationSettings);
        } else {
            fontVariation = fontVariation3;
        }
        if (Build.VERSION.SDK_INT < 28) {
            drawableManager = drawableManager3;
        } else if (!a3.hasValue(R.styleable.TextAppearance_android_textSize)) {
            drawableManager = drawableManager3;
        } else if (a3.getDimensionPixelSize(R.styleable.TextAppearance_android_textSize, -1) != 0) {
            drawableManager = drawableManager3;
        } else {
            drawableManager = drawableManager3;
            this.mView.setTextSize(0, 0.0f);
        }
        updateTypefaceAndStyle(context, a3);
        a3.recycle();
        if (textColorLink != null) {
            this.mView.setTextColor(textColorLink);
        }
        if (textColorHint != null) {
            this.mView.setHintTextColor(textColorHint);
        }
        if (textColor != null) {
            this.mView.setLinkTextColor(textColor);
        }
        if (!hasPwdTm && allCapsSet) {
            setAllCaps(allCaps);
        }
        Typeface typeface = this.mFontTypeface;
        if (typeface != null) {
            if (this.mFontWeight == -1) {
                this.mView.setTypeface(typeface, this.mStyle);
            } else {
                this.mView.setTypeface(typeface);
            }
        }
        if (fontVariation != null) {
            this.mView.setFontVariationSettings(fontVariation);
        }
        if (localeListString != null) {
            if (Build.VERSION.SDK_INT >= 24) {
                this.mView.setTextLocales(LocaleList.forLanguageTags(localeListString));
            } else if (Build.VERSION.SDK_INT >= 21) {
                String firstLanTag = localeListString.substring(0, localeListString.indexOf(44));
                this.mView.setTextLocale(Locale.forLanguageTag(firstLanTag));
            }
        }
        this.mAutoSizeTextHelper.loadFromAttributes(attrs, defStyleAttr);
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE) {
            localeListString2 = localeListString;
        } else if (this.mAutoSizeTextHelper.getAutoSizeTextType() == 0) {
            localeListString2 = localeListString;
        } else {
            int[] autoSizeTextSizesInPx = this.mAutoSizeTextHelper.getAutoSizeTextAvailableSizes();
            if (autoSizeTextSizesInPx.length <= 0) {
                localeListString2 = localeListString;
            } else if (this.mView.getAutoSizeStepGranularity() != -1.0f) {
                localeListString2 = localeListString;
                this.mView.setAutoSizeTextTypeUniformWithConfiguration(this.mAutoSizeTextHelper.getAutoSizeMinTextSize(), this.mAutoSizeTextHelper.getAutoSizeMaxTextSize(), this.mAutoSizeTextHelper.getAutoSizeStepGranularity(), 0);
            } else {
                localeListString2 = localeListString;
                this.mView.setAutoSizeTextTypeUniformWithPresetSizes(autoSizeTextSizesInPx, 0);
            }
        }
        TintTypedArray a4 = TintTypedArray.obtainStyledAttributes(context, attrs, R.styleable.AppCompatTextView);
        Drawable drawableLeft = null;
        Drawable drawableTop = null;
        int drawableLeftId = a4.getResourceId(R.styleable.AppCompatTextView_drawableLeftCompat, -1);
        if (drawableLeftId == -1) {
            drawableManager2 = drawableManager;
        } else {
            drawableManager2 = drawableManager;
            drawableLeft = drawableManager2.getDrawable(context, drawableLeftId);
        }
        Drawable drawableRight = null;
        int drawableTopId = a4.getResourceId(R.styleable.AppCompatTextView_drawableTopCompat, -1);
        if (drawableTopId != -1) {
            drawableTop = drawableManager2.getDrawable(context, drawableTopId);
        }
        int drawableRightId = a4.getResourceId(R.styleable.AppCompatTextView_drawableRightCompat, -1);
        if (drawableRightId != -1) {
            drawableRight = drawableManager2.getDrawable(context, drawableRightId);
        }
        int drawableBottomId = a4.getResourceId(R.styleable.AppCompatTextView_drawableBottomCompat, -1);
        if (drawableBottomId == -1) {
            drawableBottom = null;
        } else {
            Drawable drawableBottom2 = drawableManager2.getDrawable(context, drawableBottomId);
            drawableBottom = drawableBottom2;
        }
        int drawableStartId = a4.getResourceId(R.styleable.AppCompatTextView_drawableStartCompat, -1);
        Drawable drawableStart = drawableStartId != -1 ? drawableManager2.getDrawable(context, drawableStartId) : null;
        int drawableEndId = a4.getResourceId(R.styleable.AppCompatTextView_drawableEndCompat, -1);
        Drawable drawableEnd = drawableEndId != -1 ? drawableManager2.getDrawable(context, drawableEndId) : null;
        setCompoundDrawables(drawableLeft, drawableTop, drawableRight, drawableBottom, drawableStart, drawableEnd);
        if (a4.hasValue(R.styleable.AppCompatTextView_drawableTint)) {
            ColorStateList tintList = a4.getColorStateList(R.styleable.AppCompatTextView_drawableTint);
            TextViewCompat.setCompoundDrawableTintList(this.mView, tintList);
        }
        if (a4.hasValue(R.styleable.AppCompatTextView_drawableTintMode)) {
            PorterDuff.Mode tintMode = DrawableUtils.parseTintMode(a4.getInt(R.styleable.AppCompatTextView_drawableTintMode, -1), null);
            TextViewCompat.setCompoundDrawableTintMode(this.mView, tintMode);
        }
        int firstBaselineToTopHeight = a4.getDimensionPixelSize(R.styleable.AppCompatTextView_firstBaselineToTopHeight, -1);
        int lastBaselineToBottomHeight = a4.getDimensionPixelSize(R.styleable.AppCompatTextView_lastBaselineToBottomHeight, -1);
        int lineHeight = a4.getDimensionPixelSize(R.styleable.AppCompatTextView_lineHeight, -1);
        a4.recycle();
        if (firstBaselineToTopHeight != -1) {
            TextViewCompat.setFirstBaselineToTopHeight(this.mView, firstBaselineToTopHeight);
        }
        if (lastBaselineToBottomHeight != -1) {
            TextViewCompat.setLastBaselineToBottomHeight(this.mView, lastBaselineToBottomHeight);
        }
        if (lineHeight != -1) {
            TextViewCompat.setLineHeight(this.mView, lineHeight);
        }
    }

    private void updateTypefaceAndStyle(Context context, TintTypedArray a) {
        int fontFamilyId;
        String fontFamilyName;
        this.mStyle = a.getInt(R.styleable.TextAppearance_android_textStyle, this.mStyle);
        if (Build.VERSION.SDK_INT >= 28) {
            int i = a.getInt(R.styleable.TextAppearance_android_textFontWeight, -1);
            this.mFontWeight = i;
            if (i != -1) {
                this.mStyle = (this.mStyle & 2) | 0;
            }
        }
        if (a.hasValue(R.styleable.TextAppearance_android_fontFamily) || a.hasValue(R.styleable.TextAppearance_fontFamily)) {
            this.mFontTypeface = null;
            if (a.hasValue(R.styleable.TextAppearance_fontFamily)) {
                fontFamilyId = R.styleable.TextAppearance_fontFamily;
            } else {
                fontFamilyId = R.styleable.TextAppearance_android_fontFamily;
            }
            final int fontWeight = this.mFontWeight;
            final int style = this.mStyle;
            if (!context.isRestricted()) {
                final WeakReference<TextView> textViewWeak = new WeakReference<>(this.mView);
                ResourcesCompat.FontCallback replyCallback = new ResourcesCompat.FontCallback() { // from class: androidx.appcompat.widget.AppCompatTextHelper.1
                    @Override // androidx.core.content.res.ResourcesCompat.FontCallback
                    public void onFontRetrieved(Typeface typeface) {
                        int i2;
                        if (Build.VERSION.SDK_INT >= 28 && (i2 = fontWeight) != -1) {
                            typeface = Typeface.create(typeface, i2, (style & 2) != 0);
                        }
                        AppCompatTextHelper.this.onAsyncTypefaceReceived(textViewWeak, typeface);
                    }

                    @Override // androidx.core.content.res.ResourcesCompat.FontCallback
                    public void onFontRetrievalFailed(int reason) {
                    }
                };
                try {
                    Typeface typeface = a.getFont(fontFamilyId, this.mStyle, replyCallback);
                    if (typeface != null) {
                        if (Build.VERSION.SDK_INT >= 28 && this.mFontWeight != -1) {
                            this.mFontTypeface = Typeface.create(Typeface.create(typeface, 0), this.mFontWeight, (this.mStyle & 2) != 0);
                        } else {
                            this.mFontTypeface = typeface;
                        }
                    }
                    this.mAsyncFontPending = this.mFontTypeface == null;
                } catch (Resources.NotFoundException e) {
                } catch (UnsupportedOperationException e2) {
                }
            }
            if (this.mFontTypeface == null && (fontFamilyName = a.getString(fontFamilyId)) != null) {
                if (Build.VERSION.SDK_INT >= 28 && this.mFontWeight != -1) {
                    this.mFontTypeface = Typeface.create(Typeface.create(fontFamilyName, 0), this.mFontWeight, (this.mStyle & 2) != 0);
                } else {
                    this.mFontTypeface = Typeface.create(fontFamilyName, this.mStyle);
                }
            }
        } else if (a.hasValue(R.styleable.TextAppearance_android_typeface)) {
            this.mAsyncFontPending = false;
            int typefaceIndex = a.getInt(R.styleable.TextAppearance_android_typeface, 1);
            switch (typefaceIndex) {
                case 1:
                    this.mFontTypeface = Typeface.SANS_SERIF;
                    return;
                case 2:
                    this.mFontTypeface = Typeface.SERIF;
                    return;
                case 3:
                    this.mFontTypeface = Typeface.MONOSPACE;
                    return;
                default:
                    return;
            }
        }
    }

    void onAsyncTypefaceReceived(WeakReference<TextView> textViewWeak, final Typeface typeface) {
        if (this.mAsyncFontPending) {
            this.mFontTypeface = typeface;
            final TextView textView = textViewWeak.get();
            if (textView != null) {
                if (ViewCompat.isAttachedToWindow(textView)) {
                    final int style = this.mStyle;
                    textView.post(new Runnable() { // from class: androidx.appcompat.widget.AppCompatTextHelper.2
                        @Override // java.lang.Runnable
                        public void run() {
                            textView.setTypeface(typeface, style);
                        }
                    });
                    return;
                }
                textView.setTypeface(typeface, this.mStyle);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onSetTextAppearance(Context context, int resId) {
        String fontVariation;
        ColorStateList textColorHint;
        ColorStateList textColorLink;
        ColorStateList textColor;
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, resId, R.styleable.TextAppearance);
        if (a.hasValue(R.styleable.TextAppearance_textAllCaps)) {
            setAllCaps(a.getBoolean(R.styleable.TextAppearance_textAllCaps, false));
        }
        if (Build.VERSION.SDK_INT < 23) {
            if (a.hasValue(R.styleable.TextAppearance_android_textColor) && (textColor = a.getColorStateList(R.styleable.TextAppearance_android_textColor)) != null) {
                this.mView.setTextColor(textColor);
            }
            if (a.hasValue(R.styleable.TextAppearance_android_textColorLink) && (textColorLink = a.getColorStateList(R.styleable.TextAppearance_android_textColorLink)) != null) {
                this.mView.setLinkTextColor(textColorLink);
            }
            if (a.hasValue(R.styleable.TextAppearance_android_textColorHint) && (textColorHint = a.getColorStateList(R.styleable.TextAppearance_android_textColorHint)) != null) {
                this.mView.setHintTextColor(textColorHint);
            }
        }
        if (a.hasValue(R.styleable.TextAppearance_android_textSize) && a.getDimensionPixelSize(R.styleable.TextAppearance_android_textSize, -1) == 0) {
            this.mView.setTextSize(0, 0.0f);
        }
        updateTypefaceAndStyle(context, a);
        if (Build.VERSION.SDK_INT >= 26 && a.hasValue(R.styleable.TextAppearance_fontVariationSettings) && (fontVariation = a.getString(R.styleable.TextAppearance_fontVariationSettings)) != null) {
            this.mView.setFontVariationSettings(fontVariation);
        }
        a.recycle();
        Typeface typeface = this.mFontTypeface;
        if (typeface != null) {
            this.mView.setTypeface(typeface, this.mStyle);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAllCaps(boolean allCaps) {
        this.mView.setAllCaps(allCaps);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onSetCompoundDrawables() {
        applyCompoundDrawablesTints();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void applyCompoundDrawablesTints() {
        if (this.mDrawableLeftTint != null || this.mDrawableTopTint != null || this.mDrawableRightTint != null || this.mDrawableBottomTint != null) {
            Drawable[] compoundDrawables = this.mView.getCompoundDrawables();
            applyCompoundDrawableTint(compoundDrawables[0], this.mDrawableLeftTint);
            applyCompoundDrawableTint(compoundDrawables[1], this.mDrawableTopTint);
            applyCompoundDrawableTint(compoundDrawables[2], this.mDrawableRightTint);
            applyCompoundDrawableTint(compoundDrawables[3], this.mDrawableBottomTint);
        }
        if (Build.VERSION.SDK_INT >= 17) {
            if (this.mDrawableStartTint != null || this.mDrawableEndTint != null) {
                Drawable[] compoundDrawables2 = this.mView.getCompoundDrawablesRelative();
                applyCompoundDrawableTint(compoundDrawables2[0], this.mDrawableStartTint);
                applyCompoundDrawableTint(compoundDrawables2[2], this.mDrawableEndTint);
            }
        }
    }

    private void applyCompoundDrawableTint(Drawable drawable, TintInfo info) {
        if (drawable != null && info != null) {
            AppCompatDrawableManager.tintDrawable(drawable, info, this.mView.getDrawableState());
        }
    }

    private static TintInfo createTintInfo(Context context, AppCompatDrawableManager drawableManager, int drawableId) {
        ColorStateList tintList = drawableManager.getTintList(context, drawableId);
        if (tintList != null) {
            TintInfo tintInfo = new TintInfo();
            tintInfo.mHasTintList = true;
            tintInfo.mTintList = tintList;
            return tintInfo;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE) {
            autoSizeText();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setTextSize(int unit, float size) {
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE && !isAutoSizeEnabled()) {
            setTextSizeInternal(unit, size);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void autoSizeText() {
        this.mAutoSizeTextHelper.autoSizeText();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isAutoSizeEnabled() {
        return this.mAutoSizeTextHelper.isAutoSizeEnabled();
    }

    private void setTextSizeInternal(int unit, float size) {
        this.mAutoSizeTextHelper.setTextSizeInternal(unit, size);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAutoSizeTextTypeWithDefaults(int autoSizeTextType) {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeWithDefaults(autoSizeTextType);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAutoSizeTextTypeUniformWithConfiguration(int autoSizeMinTextSize, int autoSizeMaxTextSize, int autoSizeStepGranularity, int unit) throws IllegalArgumentException {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeUniformWithConfiguration(autoSizeMinTextSize, autoSizeMaxTextSize, autoSizeStepGranularity, unit);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAutoSizeTextTypeUniformWithPresetSizes(int[] presetSizes, int unit) throws IllegalArgumentException {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeUniformWithPresetSizes(presetSizes, unit);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAutoSizeTextType() {
        return this.mAutoSizeTextHelper.getAutoSizeTextType();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAutoSizeStepGranularity() {
        return this.mAutoSizeTextHelper.getAutoSizeStepGranularity();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAutoSizeMinTextSize() {
        return this.mAutoSizeTextHelper.getAutoSizeMinTextSize();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getAutoSizeMaxTextSize() {
        return this.mAutoSizeTextHelper.getAutoSizeMaxTextSize();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int[] getAutoSizeTextAvailableSizes() {
        return this.mAutoSizeTextHelper.getAutoSizeTextAvailableSizes();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ColorStateList getCompoundDrawableTintList() {
        TintInfo tintInfo = this.mDrawableTint;
        if (tintInfo != null) {
            return tintInfo.mTintList;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCompoundDrawableTintList(ColorStateList tintList) {
        if (this.mDrawableTint == null) {
            this.mDrawableTint = new TintInfo();
        }
        this.mDrawableTint.mTintList = tintList;
        this.mDrawableTint.mHasTintList = tintList != null;
        setCompoundTints();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PorterDuff.Mode getCompoundDrawableTintMode() {
        TintInfo tintInfo = this.mDrawableTint;
        if (tintInfo != null) {
            return tintInfo.mTintMode;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCompoundDrawableTintMode(PorterDuff.Mode tintMode) {
        if (this.mDrawableTint == null) {
            this.mDrawableTint = new TintInfo();
        }
        this.mDrawableTint.mTintMode = tintMode;
        this.mDrawableTint.mHasTintMode = tintMode != null;
        setCompoundTints();
    }

    private void setCompoundTints() {
        TintInfo tintInfo = this.mDrawableTint;
        this.mDrawableLeftTint = tintInfo;
        this.mDrawableTopTint = tintInfo;
        this.mDrawableRightTint = tintInfo;
        this.mDrawableBottomTint = tintInfo;
        this.mDrawableStartTint = tintInfo;
        this.mDrawableEndTint = tintInfo;
    }

    private void setCompoundDrawables(Drawable drawableLeft, Drawable drawableTop, Drawable drawableRight, Drawable drawableBottom, Drawable drawableStart, Drawable drawableEnd) {
        if (Build.VERSION.SDK_INT >= 17 && (drawableStart != null || drawableEnd != null)) {
            Drawable[] existingRel = this.mView.getCompoundDrawablesRelative();
            this.mView.setCompoundDrawablesRelativeWithIntrinsicBounds(drawableStart != null ? drawableStart : existingRel[0], drawableTop != null ? drawableTop : existingRel[1], drawableEnd != null ? drawableEnd : existingRel[2], drawableBottom != null ? drawableBottom : existingRel[3]);
        } else if (drawableLeft != null || drawableTop != null || drawableRight != null || drawableBottom != null) {
            if (Build.VERSION.SDK_INT >= 17) {
                Drawable[] existingRel2 = this.mView.getCompoundDrawablesRelative();
                if (existingRel2[0] != null || existingRel2[2] != null) {
                    this.mView.setCompoundDrawablesRelativeWithIntrinsicBounds(existingRel2[0], drawableTop != null ? drawableTop : existingRel2[1], existingRel2[2], drawableBottom != null ? drawableBottom : existingRel2[3]);
                    return;
                }
            }
            Drawable[] existingAbs = this.mView.getCompoundDrawables();
            this.mView.setCompoundDrawablesWithIntrinsicBounds(drawableLeft != null ? drawableLeft : existingAbs[0], drawableTop != null ? drawableTop : existingAbs[1], drawableRight != null ? drawableRight : existingAbs[2], drawableBottom != null ? drawableBottom : existingAbs[3]);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void populateSurroundingTextIfNeeded(TextView textView, InputConnection inputConnection, EditorInfo editorInfo) {
        if (Build.VERSION.SDK_INT < 30 && inputConnection != null) {
            EditorInfoCompat.setInitialSurroundingText(editorInfo, textView.getText());
        }
    }
}
