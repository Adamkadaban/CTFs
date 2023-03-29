package com.google.android.material.textfield;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.Spinner;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityManagerCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.textfield.TextInputLayout;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class DropdownMenuEndIconDelegate extends EndIconDelegate {
    private static final int ANIMATION_FADE_IN_DURATION = 67;
    private static final int ANIMATION_FADE_OUT_DURATION = 50;
    private static final boolean IS_LOLLIPOP;
    private final TextInputLayout.AccessibilityDelegate accessibilityDelegate;
    private AccessibilityManager accessibilityManager;
    private final TextInputLayout.OnEditTextAttachedListener dropdownMenuOnEditTextAttachedListener;
    private long dropdownPopupActivatedAt;
    private boolean dropdownPopupDirty;
    private final TextInputLayout.OnEndIconChangedListener endIconChangedListener;
    private final TextWatcher exposedDropdownEndIconTextWatcher;
    private ValueAnimator fadeInAnim;
    private ValueAnimator fadeOutAnim;
    private StateListDrawable filledPopupBackground;
    private boolean isEndIconChecked;
    private final View.OnAttachStateChangeListener onAttachStateChangeListener;
    private final View.OnFocusChangeListener onFocusChangeListener;
    private MaterialShapeDrawable outlinedPopupBackground;
    private final AccessibilityManagerCompat.TouchExplorationStateChangeListener touchExplorationStateChangeListener;

    static {
        IS_LOLLIPOP = Build.VERSION.SDK_INT >= 21;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DropdownMenuEndIconDelegate(TextInputLayout textInputLayout, int customEndIcon) {
        super(textInputLayout, customEndIcon);
        this.exposedDropdownEndIconTextWatcher = new TextWatcherAdapter() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.1
            @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                final AutoCompleteTextView editText = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText());
                if (DropdownMenuEndIconDelegate.this.accessibilityManager.isTouchExplorationEnabled() && DropdownMenuEndIconDelegate.isEditable(editText) && !DropdownMenuEndIconDelegate.this.endIconView.hasFocus()) {
                    editText.dismissDropDown();
                }
                editText.post(new Runnable() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        boolean isPopupShowing = editText.isPopupShowing();
                        DropdownMenuEndIconDelegate.this.setEndIconChecked(isPopupShowing);
                        DropdownMenuEndIconDelegate.this.dropdownPopupDirty = isPopupShowing;
                    }
                });
            }
        };
        this.onFocusChangeListener = new View.OnFocusChangeListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.2
            @Override // android.view.View.OnFocusChangeListener
            public void onFocusChange(View v, boolean hasFocus) {
                DropdownMenuEndIconDelegate.this.textInputLayout.setEndIconActivated(hasFocus);
                if (!hasFocus) {
                    DropdownMenuEndIconDelegate.this.setEndIconChecked(false);
                    DropdownMenuEndIconDelegate.this.dropdownPopupDirty = false;
                }
            }
        };
        this.accessibilityDelegate = new TextInputLayout.AccessibilityDelegate(this.textInputLayout) { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.3
            @Override // com.google.android.material.textfield.TextInputLayout.AccessibilityDelegate, androidx.core.view.AccessibilityDelegateCompat
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                if (!DropdownMenuEndIconDelegate.isEditable(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText())) {
                    info.setClassName(Spinner.class.getName());
                }
                if (info.isShowingHintText()) {
                    info.setHintText(null);
                }
            }

            @Override // androidx.core.view.AccessibilityDelegateCompat
            public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
                super.onPopulateAccessibilityEvent(host, event);
                AutoCompleteTextView editText = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText());
                if (event.getEventType() == 1 && DropdownMenuEndIconDelegate.this.accessibilityManager.isEnabled() && !DropdownMenuEndIconDelegate.isEditable(DropdownMenuEndIconDelegate.this.textInputLayout.getEditText())) {
                    DropdownMenuEndIconDelegate.this.showHideDropdown(editText);
                    DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
                }
            }
        };
        this.dropdownMenuOnEditTextAttachedListener = new TextInputLayout.OnEditTextAttachedListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.4
            @Override // com.google.android.material.textfield.TextInputLayout.OnEditTextAttachedListener
            public void onEditTextAttached(TextInputLayout textInputLayout2) {
                AutoCompleteTextView autoCompleteTextView = DropdownMenuEndIconDelegate.castAutoCompleteTextViewOrThrow(textInputLayout2.getEditText());
                DropdownMenuEndIconDelegate.this.setPopupBackground(autoCompleteTextView);
                DropdownMenuEndIconDelegate.this.addRippleEffect(autoCompleteTextView);
                DropdownMenuEndIconDelegate.this.setUpDropdownShowHideBehavior(autoCompleteTextView);
                autoCompleteTextView.setThreshold(0);
                autoCompleteTextView.removeTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
                autoCompleteTextView.addTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
                textInputLayout2.setEndIconCheckable(true);
                textInputLayout2.setErrorIconDrawable((Drawable) null);
                if (!DropdownMenuEndIconDelegate.isEditable(autoCompleteTextView) && DropdownMenuEndIconDelegate.this.accessibilityManager.isTouchExplorationEnabled()) {
                    ViewCompat.setImportantForAccessibility(DropdownMenuEndIconDelegate.this.endIconView, 2);
                }
                textInputLayout2.setTextInputAccessibilityDelegate(DropdownMenuEndIconDelegate.this.accessibilityDelegate);
                textInputLayout2.setEndIconVisible(true);
            }
        };
        this.endIconChangedListener = new TextInputLayout.OnEndIconChangedListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.5
            @Override // com.google.android.material.textfield.TextInputLayout.OnEndIconChangedListener
            public void onEndIconChanged(TextInputLayout textInputLayout2, int previousIcon) {
                final AutoCompleteTextView editText = (AutoCompleteTextView) textInputLayout2.getEditText();
                if (editText != null && previousIcon == 3) {
                    editText.post(new Runnable() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.5.1
                        @Override // java.lang.Runnable
                        public void run() {
                            editText.removeTextChangedListener(DropdownMenuEndIconDelegate.this.exposedDropdownEndIconTextWatcher);
                        }
                    });
                    if (editText.getOnFocusChangeListener() == DropdownMenuEndIconDelegate.this.onFocusChangeListener) {
                        editText.setOnFocusChangeListener(null);
                    }
                    editText.setOnTouchListener(null);
                    if (DropdownMenuEndIconDelegate.IS_LOLLIPOP) {
                        editText.setOnDismissListener(null);
                    }
                }
                if (previousIcon == 3) {
                    textInputLayout2.removeOnAttachStateChangeListener(DropdownMenuEndIconDelegate.this.onAttachStateChangeListener);
                    DropdownMenuEndIconDelegate.this.removeTouchExplorationStateChangeListenerIfNeeded();
                }
            }
        };
        this.onAttachStateChangeListener = new View.OnAttachStateChangeListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.6
            @Override // android.view.View.OnAttachStateChangeListener
            public void onViewAttachedToWindow(View ignored) {
                DropdownMenuEndIconDelegate.this.addTouchExplorationStateChangeListenerIfNeeded();
            }

            @Override // android.view.View.OnAttachStateChangeListener
            public void onViewDetachedFromWindow(View ignored) {
                DropdownMenuEndIconDelegate.this.removeTouchExplorationStateChangeListenerIfNeeded();
            }
        };
        this.touchExplorationStateChangeListener = new AccessibilityManagerCompat.TouchExplorationStateChangeListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.7
            @Override // androidx.core.view.accessibility.AccessibilityManagerCompat.TouchExplorationStateChangeListener
            public void onTouchExplorationStateChanged(boolean enabled) {
                AutoCompleteTextView autoCompleteTextView;
                if (DropdownMenuEndIconDelegate.this.textInputLayout != null && (autoCompleteTextView = (AutoCompleteTextView) DropdownMenuEndIconDelegate.this.textInputLayout.getEditText()) != null && !DropdownMenuEndIconDelegate.isEditable(autoCompleteTextView)) {
                    ViewCompat.setImportantForAccessibility(DropdownMenuEndIconDelegate.this.endIconView, enabled ? 2 : 1);
                }
            }
        };
        this.dropdownPopupDirty = false;
        this.isEndIconChecked = false;
        this.dropdownPopupActivatedAt = Long.MAX_VALUE;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void initialize() {
        int drawableResId;
        float popupCornerRadius = this.context.getResources().getDimensionPixelOffset(R.dimen.mtrl_shape_corner_size_small_component);
        float exposedDropdownPopupElevation = this.context.getResources().getDimensionPixelOffset(R.dimen.mtrl_exposed_dropdown_menu_popup_elevation);
        int exposedDropdownPopupVerticalPadding = this.context.getResources().getDimensionPixelOffset(R.dimen.mtrl_exposed_dropdown_menu_popup_vertical_padding);
        MaterialShapeDrawable roundedCornersPopupBackground = getPopUpMaterialShapeDrawable(popupCornerRadius, popupCornerRadius, exposedDropdownPopupElevation, exposedDropdownPopupVerticalPadding);
        MaterialShapeDrawable roundedBottomCornersPopupBackground = getPopUpMaterialShapeDrawable(0.0f, popupCornerRadius, exposedDropdownPopupElevation, exposedDropdownPopupVerticalPadding);
        this.outlinedPopupBackground = roundedCornersPopupBackground;
        StateListDrawable stateListDrawable = new StateListDrawable();
        this.filledPopupBackground = stateListDrawable;
        stateListDrawable.addState(new int[]{16842922}, roundedCornersPopupBackground);
        this.filledPopupBackground.addState(new int[0], roundedBottomCornersPopupBackground);
        if (this.customEndIcon == 0) {
            drawableResId = IS_LOLLIPOP ? R.drawable.mtrl_dropdown_arrow : R.drawable.mtrl_ic_arrow_drop_down;
        } else {
            drawableResId = this.customEndIcon;
        }
        this.textInputLayout.setEndIconDrawable(drawableResId);
        this.textInputLayout.setEndIconContentDescription(this.textInputLayout.getResources().getText(R.string.exposed_dropdown_menu_content_description));
        this.textInputLayout.setEndIconOnClickListener(new View.OnClickListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.8
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                AutoCompleteTextView editText = (AutoCompleteTextView) DropdownMenuEndIconDelegate.this.textInputLayout.getEditText();
                DropdownMenuEndIconDelegate.this.showHideDropdown(editText);
            }
        });
        this.textInputLayout.addOnEditTextAttachedListener(this.dropdownMenuOnEditTextAttachedListener);
        this.textInputLayout.addOnEndIconChangedListener(this.endIconChangedListener);
        initAnimators();
        this.accessibilityManager = (AccessibilityManager) this.context.getSystemService("accessibility");
        this.textInputLayout.addOnAttachStateChangeListener(this.onAttachStateChangeListener);
        addTouchExplorationStateChangeListenerIfNeeded();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean shouldTintIconOnError() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isBoxBackgroundModeSupported(int boxBackgroundMode) {
        return boxBackgroundMode != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showHideDropdown(AutoCompleteTextView editText) {
        if (editText == null) {
            return;
        }
        if (isDropdownPopupActive()) {
            this.dropdownPopupDirty = false;
        }
        if (!this.dropdownPopupDirty) {
            if (IS_LOLLIPOP) {
                setEndIconChecked(!this.isEndIconChecked);
            } else {
                this.isEndIconChecked = !this.isEndIconChecked;
                this.endIconView.toggle();
            }
            if (this.isEndIconChecked) {
                editText.requestFocus();
                editText.showDropDown();
                return;
            }
            editText.dismissDropDown();
            return;
        }
        this.dropdownPopupDirty = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setPopupBackground(AutoCompleteTextView editText) {
        if (IS_LOLLIPOP) {
            int boxBackgroundMode = this.textInputLayout.getBoxBackgroundMode();
            if (boxBackgroundMode == 2) {
                editText.setDropDownBackgroundDrawable(this.outlinedPopupBackground);
            } else if (boxBackgroundMode == 1) {
                editText.setDropDownBackgroundDrawable(this.filledPopupBackground);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateOutlinedRippleEffect(AutoCompleteTextView editText) {
        if (isEditable(editText) || this.textInputLayout.getBoxBackgroundMode() != 2 || !(editText.getBackground() instanceof LayerDrawable)) {
            return;
        }
        addRippleEffect(editText);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addRippleEffect(AutoCompleteTextView editText) {
        if (isEditable(editText)) {
            return;
        }
        int boxBackgroundMode = this.textInputLayout.getBoxBackgroundMode();
        MaterialShapeDrawable boxBackground = this.textInputLayout.getBoxBackground();
        int rippleColor = MaterialColors.getColor(editText, R.attr.colorControlHighlight);
        int[][] states = {new int[]{16842919}, new int[0]};
        if (boxBackgroundMode == 2) {
            addRippleEffectOnOutlinedLayout(editText, rippleColor, states, boxBackground);
        } else if (boxBackgroundMode == 1) {
            addRippleEffectOnFilledLayout(editText, rippleColor, states, boxBackground);
        }
    }

    private void addRippleEffectOnOutlinedLayout(AutoCompleteTextView editText, int rippleColor, int[][] states, MaterialShapeDrawable boxBackground) {
        LayerDrawable editTextBackground;
        int surfaceColor = MaterialColors.getColor(editText, R.attr.colorSurface);
        MaterialShapeDrawable rippleBackground = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
        int pressedBackgroundColor = MaterialColors.layer(rippleColor, surfaceColor, 0.1f);
        int[] rippleBackgroundColors = {pressedBackgroundColor, 0};
        rippleBackground.setFillColor(new ColorStateList(states, rippleBackgroundColors));
        if (IS_LOLLIPOP) {
            rippleBackground.setTint(surfaceColor);
            int[] colors = {pressedBackgroundColor, surfaceColor};
            ColorStateList rippleColorStateList = new ColorStateList(states, colors);
            MaterialShapeDrawable mask = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
            mask.setTint(-1);
            Drawable rippleDrawable = new RippleDrawable(rippleColorStateList, rippleBackground, mask);
            Drawable[] layers = {rippleDrawable, boxBackground};
            editTextBackground = new LayerDrawable(layers);
        } else {
            Drawable[] layers2 = {rippleBackground, boxBackground};
            editTextBackground = new LayerDrawable(layers2);
        }
        ViewCompat.setBackground(editText, editTextBackground);
    }

    private void addRippleEffectOnFilledLayout(AutoCompleteTextView editText, int rippleColor, int[][] states, MaterialShapeDrawable boxBackground) {
        int boxBackgroundColor = this.textInputLayout.getBoxBackgroundColor();
        int pressedBackgroundColor = MaterialColors.layer(rippleColor, boxBackgroundColor, 0.1f);
        int[] colors = {pressedBackgroundColor, boxBackgroundColor};
        if (IS_LOLLIPOP) {
            ColorStateList rippleColorStateList = new ColorStateList(states, colors);
            Drawable editTextBackground = new RippleDrawable(rippleColorStateList, boxBackground, boxBackground);
            ViewCompat.setBackground(editText, editTextBackground);
            return;
        }
        MaterialShapeDrawable rippleBackground = new MaterialShapeDrawable(boxBackground.getShapeAppearanceModel());
        rippleBackground.setFillColor(new ColorStateList(states, colors));
        Drawable[] layers = {boxBackground, rippleBackground};
        LayerDrawable editTextBackground2 = new LayerDrawable(layers);
        int start = ViewCompat.getPaddingStart(editText);
        int top = editText.getPaddingTop();
        int end = ViewCompat.getPaddingEnd(editText);
        int bottom = editText.getPaddingBottom();
        ViewCompat.setBackground(editText, editTextBackground2);
        ViewCompat.setPaddingRelative(editText, start, top, end, bottom);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setUpDropdownShowHideBehavior(final AutoCompleteTextView editText) {
        editText.setOnTouchListener(new View.OnTouchListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.9
            @Override // android.view.View.OnTouchListener
            public boolean onTouch(View v, MotionEvent event) {
                if (event.getAction() == 1) {
                    if (DropdownMenuEndIconDelegate.this.isDropdownPopupActive()) {
                        DropdownMenuEndIconDelegate.this.dropdownPopupDirty = false;
                    }
                    DropdownMenuEndIconDelegate.this.showHideDropdown(editText);
                    DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
                }
                return false;
            }
        });
        editText.setOnFocusChangeListener(this.onFocusChangeListener);
        if (IS_LOLLIPOP) {
            editText.setOnDismissListener(new AutoCompleteTextView.OnDismissListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.10
                @Override // android.widget.AutoCompleteTextView.OnDismissListener
                public void onDismiss() {
                    DropdownMenuEndIconDelegate.this.updateDropdownPopupDirty();
                    DropdownMenuEndIconDelegate.this.setEndIconChecked(false);
                }
            });
        }
    }

    private MaterialShapeDrawable getPopUpMaterialShapeDrawable(float topCornerRadius, float bottomCornerRadius, float elevation, int verticalPadding) {
        ShapeAppearanceModel shapeAppearanceModel = ShapeAppearanceModel.builder().setTopLeftCornerSize(topCornerRadius).setTopRightCornerSize(topCornerRadius).setBottomLeftCornerSize(bottomCornerRadius).setBottomRightCornerSize(bottomCornerRadius).build();
        MaterialShapeDrawable popupDrawable = MaterialShapeDrawable.createWithElevationOverlay(this.context, elevation);
        popupDrawable.setShapeAppearanceModel(shapeAppearanceModel);
        popupDrawable.setPadding(0, verticalPadding, 0, verticalPadding);
        return popupDrawable;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isDropdownPopupActive() {
        long activeFor = System.currentTimeMillis() - this.dropdownPopupActivatedAt;
        return activeFor < 0 || activeFor > 300;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static AutoCompleteTextView castAutoCompleteTextViewOrThrow(EditText editText) {
        if (!(editText instanceof AutoCompleteTextView)) {
            throw new RuntimeException("EditText needs to be an AutoCompleteTextView if an Exposed Dropdown Menu is being used.");
        }
        return (AutoCompleteTextView) editText;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateDropdownPopupDirty() {
        this.dropdownPopupDirty = true;
        this.dropdownPopupActivatedAt = System.currentTimeMillis();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean isEditable(EditText editText) {
        return editText.getKeyListener() != null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setEndIconChecked(boolean checked) {
        if (this.isEndIconChecked != checked) {
            this.isEndIconChecked = checked;
            this.fadeInAnim.cancel();
            this.fadeOutAnim.start();
        }
    }

    private void initAnimators() {
        this.fadeInAnim = getAlphaAnimator(67, 0.0f, 1.0f);
        ValueAnimator alphaAnimator = getAlphaAnimator(50, 1.0f, 0.0f);
        this.fadeOutAnim = alphaAnimator;
        alphaAnimator.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.11
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                DropdownMenuEndIconDelegate.this.endIconView.setChecked(DropdownMenuEndIconDelegate.this.isEndIconChecked);
                DropdownMenuEndIconDelegate.this.fadeInAnim.start();
            }
        });
    }

    private ValueAnimator getAlphaAnimator(int duration, float... values) {
        ValueAnimator animator = ValueAnimator.ofFloat(values);
        animator.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        animator.setDuration(duration);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.12
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator animation) {
                float alpha = ((Float) animation.getAnimatedValue()).floatValue();
                DropdownMenuEndIconDelegate.this.endIconView.setAlpha(alpha);
            }
        });
        return animator;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addTouchExplorationStateChangeListenerIfNeeded() {
        if (this.accessibilityManager != null && this.textInputLayout != null && ViewCompat.isAttachedToWindow(this.textInputLayout)) {
            AccessibilityManagerCompat.addTouchExplorationStateChangeListener(this.accessibilityManager, this.touchExplorationStateChangeListener);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeTouchExplorationStateChangeListenerIfNeeded() {
        AccessibilityManager accessibilityManager = this.accessibilityManager;
        if (accessibilityManager != null) {
            AccessibilityManagerCompat.removeTouchExplorationStateChangeListener(accessibilityManager, this.touchExplorationStateChangeListener);
        }
    }
}
