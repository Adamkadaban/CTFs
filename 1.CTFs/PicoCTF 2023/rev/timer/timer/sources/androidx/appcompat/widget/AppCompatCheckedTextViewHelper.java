package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.CheckedTextView;
import androidx.appcompat.R;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import androidx.core.widget.CheckedTextViewCompat;
/* loaded from: classes.dex */
class AppCompatCheckedTextViewHelper {
    private ColorStateList mCheckMarkTintList = null;
    private PorterDuff.Mode mCheckMarkTintMode = null;
    private boolean mHasCheckMarkTint = false;
    private boolean mHasCheckMarkTintMode = false;
    private boolean mSkipNextApply;
    private final CheckedTextView mView;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppCompatCheckedTextViewHelper(CheckedTextView view) {
        this.mView = view;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        int resourceId;
        int resourceId2;
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(this.mView.getContext(), attrs, R.styleable.CheckedTextView, defStyleAttr, 0);
        CheckedTextView checkedTextView = this.mView;
        ViewCompat.saveAttributeDataForStyleable(checkedTextView, checkedTextView.getContext(), R.styleable.CheckedTextView, attrs, a.getWrappedTypeArray(), defStyleAttr, 0);
        boolean checkMarkDrawableLoaded = false;
        try {
            if (a.hasValue(R.styleable.CheckedTextView_checkMarkCompat) && (resourceId2 = a.getResourceId(R.styleable.CheckedTextView_checkMarkCompat, 0)) != 0) {
                try {
                    CheckedTextView checkedTextView2 = this.mView;
                    checkedTextView2.setCheckMarkDrawable(AppCompatResources.getDrawable(checkedTextView2.getContext(), resourceId2));
                    checkMarkDrawableLoaded = true;
                } catch (Resources.NotFoundException e) {
                }
            }
            if (!checkMarkDrawableLoaded && a.hasValue(R.styleable.CheckedTextView_android_checkMark) && (resourceId = a.getResourceId(R.styleable.CheckedTextView_android_checkMark, 0)) != 0) {
                CheckedTextView checkedTextView3 = this.mView;
                checkedTextView3.setCheckMarkDrawable(AppCompatResources.getDrawable(checkedTextView3.getContext(), resourceId));
            }
            if (a.hasValue(R.styleable.CheckedTextView_checkMarkTint)) {
                CheckedTextViewCompat.setCheckMarkTintList(this.mView, a.getColorStateList(R.styleable.CheckedTextView_checkMarkTint));
            }
            if (a.hasValue(R.styleable.CheckedTextView_checkMarkTintMode)) {
                CheckedTextViewCompat.setCheckMarkTintMode(this.mView, DrawableUtils.parseTintMode(a.getInt(R.styleable.CheckedTextView_checkMarkTintMode, -1), null));
            }
        } finally {
            a.recycle();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSupportCheckMarkTintList(ColorStateList tint) {
        this.mCheckMarkTintList = tint;
        this.mHasCheckMarkTint = true;
        applyCheckMarkTint();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ColorStateList getSupportCheckMarkTintList() {
        return this.mCheckMarkTintList;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSupportCheckMarkTintMode(PorterDuff.Mode tintMode) {
        this.mCheckMarkTintMode = tintMode;
        this.mHasCheckMarkTintMode = true;
        applyCheckMarkTint();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PorterDuff.Mode getSupportCheckMarkTintMode() {
        return this.mCheckMarkTintMode;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onSetCheckMarkDrawable() {
        if (this.mSkipNextApply) {
            this.mSkipNextApply = false;
            return;
        }
        this.mSkipNextApply = true;
        applyCheckMarkTint();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void applyCheckMarkTint() {
        Drawable checkMarkDrawable = CheckedTextViewCompat.getCheckMarkDrawable(this.mView);
        if (checkMarkDrawable != null) {
            if (this.mHasCheckMarkTint || this.mHasCheckMarkTintMode) {
                Drawable checkMarkDrawable2 = DrawableCompat.wrap(checkMarkDrawable).mutate();
                if (this.mHasCheckMarkTint) {
                    DrawableCompat.setTintList(checkMarkDrawable2, this.mCheckMarkTintList);
                }
                if (this.mHasCheckMarkTintMode) {
                    DrawableCompat.setTintMode(checkMarkDrawable2, this.mCheckMarkTintMode);
                }
                if (checkMarkDrawable2.isStateful()) {
                    checkMarkDrawable2.setState(this.mView.getDrawableState());
                }
                this.mView.setCheckMarkDrawable(checkMarkDrawable2);
            }
        }
    }
}
