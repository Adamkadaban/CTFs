package com.google.android.material.textfield;

import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.EditText;
import com.google.android.material.R;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.textfield.TextInputLayout;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class PasswordToggleEndIconDelegate extends EndIconDelegate {
    private final TextInputLayout.OnEditTextAttachedListener onEditTextAttachedListener;
    private final TextInputLayout.OnEndIconChangedListener onEndIconChangedListener;
    private final TextWatcher textWatcher;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PasswordToggleEndIconDelegate(TextInputLayout textInputLayout, int customEndIcon) {
        super(textInputLayout, customEndIcon);
        this.textWatcher = new TextWatcherAdapter() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate.1
            @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                PasswordToggleEndIconDelegate.this.endIconView.setChecked(!PasswordToggleEndIconDelegate.this.hasPasswordTransformation());
            }
        };
        this.onEditTextAttachedListener = new TextInputLayout.OnEditTextAttachedListener() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate.2
            @Override // com.google.android.material.textfield.TextInputLayout.OnEditTextAttachedListener
            public void onEditTextAttached(TextInputLayout textInputLayout2) {
                EditText editText = textInputLayout2.getEditText();
                PasswordToggleEndIconDelegate.this.endIconView.setChecked(!PasswordToggleEndIconDelegate.this.hasPasswordTransformation());
                editText.removeTextChangedListener(PasswordToggleEndIconDelegate.this.textWatcher);
                editText.addTextChangedListener(PasswordToggleEndIconDelegate.this.textWatcher);
            }
        };
        this.onEndIconChangedListener = new TextInputLayout.OnEndIconChangedListener() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate.3
            @Override // com.google.android.material.textfield.TextInputLayout.OnEndIconChangedListener
            public void onEndIconChanged(TextInputLayout textInputLayout2, int previousIcon) {
                final EditText editText = textInputLayout2.getEditText();
                if (editText != null && previousIcon == 1) {
                    editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
                    editText.post(new Runnable() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate.3.1
                        @Override // java.lang.Runnable
                        public void run() {
                            editText.removeTextChangedListener(PasswordToggleEndIconDelegate.this.textWatcher);
                        }
                    });
                }
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void initialize() {
        this.textInputLayout.setEndIconDrawable(this.customEndIcon == 0 ? R.drawable.design_password_eye : this.customEndIcon);
        this.textInputLayout.setEndIconContentDescription(this.textInputLayout.getResources().getText(R.string.password_toggle_content_description));
        this.textInputLayout.setEndIconVisible(true);
        this.textInputLayout.setEndIconCheckable(true);
        this.textInputLayout.setEndIconOnClickListener(new View.OnClickListener() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate.4
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                EditText editText = PasswordToggleEndIconDelegate.this.textInputLayout.getEditText();
                if (editText == null) {
                    return;
                }
                int selection = editText.getSelectionEnd();
                if (PasswordToggleEndIconDelegate.this.hasPasswordTransformation()) {
                    editText.setTransformationMethod(null);
                } else {
                    editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
                }
                if (selection >= 0) {
                    editText.setSelection(selection);
                }
                PasswordToggleEndIconDelegate.this.textInputLayout.refreshEndIconDrawableState();
            }
        });
        this.textInputLayout.addOnEditTextAttachedListener(this.onEditTextAttachedListener);
        this.textInputLayout.addOnEndIconChangedListener(this.onEndIconChangedListener);
        EditText editText = this.textInputLayout.getEditText();
        if (isInputTypePassword(editText)) {
            editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasPasswordTransformation() {
        EditText editText = this.textInputLayout.getEditText();
        return editText != null && (editText.getTransformationMethod() instanceof PasswordTransformationMethod);
    }

    private static boolean isInputTypePassword(EditText editText) {
        return editText != null && (editText.getInputType() == 16 || editText.getInputType() == 128 || editText.getInputType() == 144 || editText.getInputType() == 224);
    }
}
