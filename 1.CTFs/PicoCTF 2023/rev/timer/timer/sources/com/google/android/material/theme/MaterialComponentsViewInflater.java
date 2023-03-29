package com.google.android.material.theme;

import android.content.Context;
import android.util.AttributeSet;
import androidx.appcompat.app.AppCompatViewInflater;
import androidx.appcompat.widget.AppCompatAutoCompleteTextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.appcompat.widget.AppCompatRadioButton;
import androidx.appcompat.widget.AppCompatTextView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.radiobutton.MaterialRadioButton;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;
import com.google.android.material.textview.MaterialTextView;
/* loaded from: classes.dex */
public class MaterialComponentsViewInflater extends AppCompatViewInflater {
    @Override // androidx.appcompat.app.AppCompatViewInflater
    protected AppCompatButton createButton(Context context, AttributeSet attrs) {
        return new MaterialButton(context, attrs);
    }

    @Override // androidx.appcompat.app.AppCompatViewInflater
    protected AppCompatCheckBox createCheckBox(Context context, AttributeSet attrs) {
        return new MaterialCheckBox(context, attrs);
    }

    @Override // androidx.appcompat.app.AppCompatViewInflater
    protected AppCompatRadioButton createRadioButton(Context context, AttributeSet attrs) {
        return new MaterialRadioButton(context, attrs);
    }

    @Override // androidx.appcompat.app.AppCompatViewInflater
    protected AppCompatTextView createTextView(Context context, AttributeSet attrs) {
        return new MaterialTextView(context, attrs);
    }

    @Override // androidx.appcompat.app.AppCompatViewInflater
    protected AppCompatAutoCompleteTextView createAutoCompleteTextView(Context context, AttributeSet attrs) {
        return new MaterialAutoCompleteTextView(context, attrs);
    }
}
