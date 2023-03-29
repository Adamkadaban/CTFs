package com.google.android.material.timepicker;

import android.text.Editable;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import com.google.android.material.textfield.TextInputLayout;
/* loaded from: classes.dex */
class TimePickerTextInputKeyController implements TextView.OnEditorActionListener, View.OnKeyListener {
    private final ChipTextInputComboView hourLayoutComboView;
    private boolean keyListenerRunning = false;
    private final ChipTextInputComboView minuteLayoutComboView;
    private final TimeModel time;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TimePickerTextInputKeyController(ChipTextInputComboView hourLayoutComboView, ChipTextInputComboView minuteLayoutComboView, TimeModel time) {
        this.hourLayoutComboView = hourLayoutComboView;
        this.minuteLayoutComboView = minuteLayoutComboView;
        this.time = time;
    }

    public void bind() {
        TextInputLayout hourLayout = this.hourLayoutComboView.getTextInput();
        TextInputLayout minuteLayout = this.minuteLayoutComboView.getTextInput();
        EditText hourEditText = hourLayout.getEditText();
        EditText minuteEditText = minuteLayout.getEditText();
        hourEditText.setImeOptions(268435461);
        minuteEditText.setImeOptions(268435462);
        hourEditText.setOnEditorActionListener(this);
        hourEditText.setOnKeyListener(this);
        minuteEditText.setOnKeyListener(this);
    }

    private void moveSelection(int selection) {
        this.minuteLayoutComboView.setChecked(selection == 12);
        this.hourLayoutComboView.setChecked(selection == 10);
        this.time.selection = selection;
    }

    @Override // android.widget.TextView.OnEditorActionListener
    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
        boolean actionNext = actionId == 5;
        if (actionNext) {
            moveSelection(12);
        }
        return actionNext;
    }

    @Override // android.view.View.OnKeyListener
    public boolean onKey(View view, int keyCode, KeyEvent event) {
        boolean ret;
        if (this.keyListenerRunning) {
            return false;
        }
        this.keyListenerRunning = true;
        EditText editText = (EditText) view;
        if (this.time.selection == 12) {
            ret = onMinuteKeyPress(keyCode, event, editText);
        } else {
            ret = onHourKeyPress(keyCode, event, editText);
        }
        this.keyListenerRunning = false;
        return ret;
    }

    private boolean onMinuteKeyPress(int keyCode, KeyEvent event, EditText editText) {
        boolean switchFocus = keyCode == 67 && event.getAction() == 0 && TextUtils.isEmpty(editText.getText());
        if (switchFocus) {
            moveSelection(10);
            return true;
        }
        return false;
    }

    private boolean onHourKeyPress(int keyCode, KeyEvent event, EditText editText) {
        Editable text = editText.getText();
        if (text == null) {
            return false;
        }
        boolean switchFocus = keyCode >= 7 && keyCode <= 16 && event.getAction() == 1 && editText.getSelectionStart() == 2 && text.length() == 2;
        if (!switchFocus) {
            return false;
        }
        moveSelection(12);
        return true;
    }
}
