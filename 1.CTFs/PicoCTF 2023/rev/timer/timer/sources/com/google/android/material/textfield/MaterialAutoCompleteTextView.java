package com.google.android.material.textfield;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Filterable;
import android.widget.ListAdapter;
import androidx.appcompat.widget.AppCompatAutoCompleteTextView;
import androidx.appcompat.widget.ListPopupWindow;
import com.google.android.material.R;
import com.google.android.material.internal.ManufacturerUtils;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.theme.overlay.MaterialThemeOverlay;
/* loaded from: classes.dex */
public class MaterialAutoCompleteTextView extends AppCompatAutoCompleteTextView {
    private static final int MAX_ITEMS_MEASURED = 15;
    private final AccessibilityManager accessibilityManager;
    private final ListPopupWindow modalListPopup;
    private final int simpleItemLayout;
    private final Rect tempRect;

    public MaterialAutoCompleteTextView(Context context) {
        this(context, null);
    }

    public MaterialAutoCompleteTextView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, R.attr.autoCompleteTextViewStyle);
    }

    public MaterialAutoCompleteTextView(Context context, AttributeSet attributeSet, int defStyleAttr) {
        super(MaterialThemeOverlay.wrap(context, attributeSet, defStyleAttr, 0), attributeSet, defStyleAttr);
        this.tempRect = new Rect();
        Context context2 = getContext();
        TypedArray attributes = ThemeEnforcement.obtainStyledAttributes(context2, attributeSet, R.styleable.MaterialAutoCompleteTextView, defStyleAttr, R.style.Widget_AppCompat_AutoCompleteTextView, new int[0]);
        if (attributes.hasValue(R.styleable.MaterialAutoCompleteTextView_android_inputType)) {
            int inputType = attributes.getInt(R.styleable.MaterialAutoCompleteTextView_android_inputType, 0);
            if (inputType == 0) {
                setKeyListener(null);
            }
        }
        int inputType2 = R.styleable.MaterialAutoCompleteTextView_simpleItemLayout;
        this.simpleItemLayout = attributes.getResourceId(inputType2, R.layout.mtrl_auto_complete_simple_item);
        this.accessibilityManager = (AccessibilityManager) context2.getSystemService("accessibility");
        ListPopupWindow listPopupWindow = new ListPopupWindow(context2);
        this.modalListPopup = listPopupWindow;
        listPopupWindow.setModal(true);
        listPopupWindow.setAnchorView(this);
        listPopupWindow.setInputMethodMode(2);
        listPopupWindow.setAdapter(getAdapter());
        listPopupWindow.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: com.google.android.material.textfield.MaterialAutoCompleteTextView.1
            @Override // android.widget.AdapterView.OnItemClickListener
            public void onItemClick(AdapterView<?> parent, View selectedView, int position, long id) {
                MaterialAutoCompleteTextView materialAutoCompleteTextView = MaterialAutoCompleteTextView.this;
                Object selectedItem = position < 0 ? materialAutoCompleteTextView.modalListPopup.getSelectedItem() : materialAutoCompleteTextView.getAdapter().getItem(position);
                MaterialAutoCompleteTextView.this.updateText(selectedItem);
                AdapterView.OnItemClickListener userOnitemClickListener = MaterialAutoCompleteTextView.this.getOnItemClickListener();
                if (userOnitemClickListener != null) {
                    if (selectedView == null || position < 0) {
                        selectedView = MaterialAutoCompleteTextView.this.modalListPopup.getSelectedView();
                        position = MaterialAutoCompleteTextView.this.modalListPopup.getSelectedItemPosition();
                        id = MaterialAutoCompleteTextView.this.modalListPopup.getSelectedItemId();
                    }
                    userOnitemClickListener.onItemClick(MaterialAutoCompleteTextView.this.modalListPopup.getListView(), selectedView, position, id);
                }
                MaterialAutoCompleteTextView.this.modalListPopup.dismiss();
            }
        });
        if (attributes.hasValue(R.styleable.MaterialAutoCompleteTextView_simpleItems)) {
            setSimpleItems(attributes.getResourceId(R.styleable.MaterialAutoCompleteTextView_simpleItems, 0));
        }
        attributes.recycle();
    }

    @Override // android.widget.AutoCompleteTextView
    public void showDropDown() {
        AccessibilityManager accessibilityManager = this.accessibilityManager;
        if (accessibilityManager != null && accessibilityManager.isTouchExplorationEnabled()) {
            this.modalListPopup.show();
        } else {
            super.showDropDown();
        }
    }

    @Override // android.widget.AutoCompleteTextView
    public <T extends ListAdapter & Filterable> void setAdapter(T adapter) {
        super.setAdapter(adapter);
        this.modalListPopup.setAdapter(getAdapter());
    }

    public void setSimpleItems(int stringArrayResId) {
        setSimpleItems(getResources().getStringArray(stringArrayResId));
    }

    public void setSimpleItems(String[] stringArray) {
        setAdapter(new ArrayAdapter(getContext(), this.simpleItemLayout, stringArray));
    }

    @Override // android.widget.AutoCompleteTextView, android.widget.TextView, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        TextInputLayout layout = findTextInputLayoutAncestor();
        if (layout != null && layout.isProvidingHint() && super.getHint() == null && ManufacturerUtils.isMeizuDevice()) {
            setHint("");
        }
    }

    @Override // android.widget.TextView
    public CharSequence getHint() {
        TextInputLayout textInputLayout = findTextInputLayoutAncestor();
        if (textInputLayout != null && textInputLayout.isProvidingHint()) {
            return textInputLayout.getHint();
        }
        return super.getHint();
    }

    @Override // android.widget.TextView, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (View.MeasureSpec.getMode(widthMeasureSpec) == Integer.MIN_VALUE) {
            int measuredWidth = getMeasuredWidth();
            setMeasuredDimension(Math.min(Math.max(measuredWidth, measureContentWidth()), View.MeasureSpec.getSize(widthMeasureSpec)), getMeasuredHeight());
        }
    }

    private int measureContentWidth() {
        ListAdapter adapter = getAdapter();
        TextInputLayout textInputLayout = findTextInputLayoutAncestor();
        if (adapter == null || textInputLayout == null) {
            return 0;
        }
        int width = 0;
        View itemView = null;
        int itemType = 0;
        int widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 0);
        int heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 0);
        int start = Math.max(0, this.modalListPopup.getSelectedItemPosition());
        int end = Math.min(adapter.getCount(), start + 15);
        int start2 = Math.max(0, end - 15);
        for (int i = start2; i < end; i++) {
            int positionType = adapter.getItemViewType(i);
            if (positionType != itemType) {
                itemType = positionType;
                itemView = null;
            }
            itemView = adapter.getView(i, itemView, textInputLayout);
            if (itemView.getLayoutParams() == null) {
                itemView.setLayoutParams(new ViewGroup.LayoutParams(-2, -2));
            }
            itemView.measure(widthMeasureSpec, heightMeasureSpec);
            width = Math.max(width, itemView.getMeasuredWidth());
        }
        Drawable background = this.modalListPopup.getBackground();
        if (background != null) {
            background.getPadding(this.tempRect);
            width += this.tempRect.left + this.tempRect.right;
        }
        int iconWidth = textInputLayout.getEndIconView().getMeasuredWidth();
        return width + iconWidth;
    }

    private TextInputLayout findTextInputLayoutAncestor() {
        for (ViewParent parent = getParent(); parent != null; parent = parent.getParent()) {
            if (parent instanceof TextInputLayout) {
                return (TextInputLayout) parent;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public <T extends ListAdapter & Filterable> void updateText(Object selectedItem) {
        if (Build.VERSION.SDK_INT >= 17) {
            setText(convertSelectionToString(selectedItem), false);
            return;
        }
        ListAdapter adapter = getAdapter();
        setAdapter(null);
        setText(convertSelectionToString(selectedItem));
        setAdapter(adapter);
    }
}
