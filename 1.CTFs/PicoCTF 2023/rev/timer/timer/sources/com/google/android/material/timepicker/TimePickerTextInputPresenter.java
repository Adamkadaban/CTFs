package com.google.android.material.timepicker;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.ContextCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.R;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.timepicker.TimePickerView;
import java.lang.reflect.Field;
import java.util.Locale;
/* loaded from: classes.dex */
class TimePickerTextInputPresenter implements TimePickerView.OnSelectionChange, TimePickerPresenter {
    private final TimePickerTextInputKeyController controller;
    private final EditText hourEditText;
    private final ChipTextInputComboView hourTextInput;
    private final EditText minuteEditText;
    private final ChipTextInputComboView minuteTextInput;
    private final TimeModel time;
    private final LinearLayout timePickerView;
    private MaterialButtonToggleGroup toggle;
    private final TextWatcher minuteTextWatcher = new TextWatcherAdapter() { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.1
        @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
        public void afterTextChanged(Editable s) {
            try {
                if (TextUtils.isEmpty(s)) {
                    TimePickerTextInputPresenter.this.time.setMinute(0);
                    return;
                }
                int minute = Integer.parseInt(s.toString());
                TimePickerTextInputPresenter.this.time.setMinute(minute);
            } catch (NumberFormatException e) {
            }
        }
    };
    private final TextWatcher hourTextWatcher = new TextWatcherAdapter() { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.2
        @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
        public void afterTextChanged(Editable s) {
            try {
                if (TextUtils.isEmpty(s)) {
                    TimePickerTextInputPresenter.this.time.setHour(0);
                    return;
                }
                int hour = Integer.parseInt(s.toString());
                TimePickerTextInputPresenter.this.time.setHour(hour);
            } catch (NumberFormatException e) {
            }
        }
    };

    public TimePickerTextInputPresenter(LinearLayout timePickerView, final TimeModel time) {
        this.timePickerView = timePickerView;
        this.time = time;
        Resources res = timePickerView.getResources();
        ChipTextInputComboView chipTextInputComboView = (ChipTextInputComboView) timePickerView.findViewById(R.id.material_minute_text_input);
        this.minuteTextInput = chipTextInputComboView;
        ChipTextInputComboView chipTextInputComboView2 = (ChipTextInputComboView) timePickerView.findViewById(R.id.material_hour_text_input);
        this.hourTextInput = chipTextInputComboView2;
        TextView minuteLabel = (TextView) chipTextInputComboView.findViewById(R.id.material_label);
        TextView hourLabel = (TextView) chipTextInputComboView2.findViewById(R.id.material_label);
        minuteLabel.setText(res.getString(R.string.material_timepicker_minute));
        hourLabel.setText(res.getString(R.string.material_timepicker_hour));
        chipTextInputComboView.setTag(R.id.selection_type, 12);
        chipTextInputComboView2.setTag(R.id.selection_type, 10);
        if (time.format == 0) {
            setupPeriodToggle();
        }
        View.OnClickListener onClickListener = new View.OnClickListener() { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                TimePickerTextInputPresenter.this.onSelectionChanged(((Integer) v.getTag(R.id.selection_type)).intValue());
            }
        };
        chipTextInputComboView2.setOnClickListener(onClickListener);
        chipTextInputComboView.setOnClickListener(onClickListener);
        chipTextInputComboView2.addInputFilter(time.getHourInputValidator());
        chipTextInputComboView.addInputFilter(time.getMinuteInputValidator());
        EditText editText = chipTextInputComboView2.getTextInput().getEditText();
        this.hourEditText = editText;
        EditText editText2 = chipTextInputComboView.getTextInput().getEditText();
        this.minuteEditText = editText2;
        if (Build.VERSION.SDK_INT < 21) {
            int primaryColor = MaterialColors.getColor(timePickerView, R.attr.colorPrimary);
            setCursorDrawableColor(editText, primaryColor);
            setCursorDrawableColor(editText2, primaryColor);
        }
        this.controller = new TimePickerTextInputKeyController(chipTextInputComboView2, chipTextInputComboView, time);
        chipTextInputComboView2.setChipDelegate(new ClickActionDelegate(timePickerView.getContext(), R.string.material_hour_selection) { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.4
            @Override // com.google.android.material.timepicker.ClickActionDelegate, androidx.core.view.AccessibilityDelegateCompat
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.setContentDescription(host.getResources().getString(R.string.material_hour_suffix, String.valueOf(time.getHourForDisplay())));
            }
        });
        chipTextInputComboView.setChipDelegate(new ClickActionDelegate(timePickerView.getContext(), R.string.material_minute_selection) { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.5
            @Override // com.google.android.material.timepicker.ClickActionDelegate, androidx.core.view.AccessibilityDelegateCompat
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.setContentDescription(host.getResources().getString(R.string.material_minute_suffix, String.valueOf(time.minute)));
            }
        });
        initialize();
    }

    @Override // com.google.android.material.timepicker.TimePickerPresenter
    public void initialize() {
        addTextWatchers();
        setTime(this.time);
        this.controller.bind();
    }

    private void addTextWatchers() {
        this.hourEditText.addTextChangedListener(this.hourTextWatcher);
        this.minuteEditText.addTextChangedListener(this.minuteTextWatcher);
    }

    private void removeTextWatchers() {
        this.hourEditText.removeTextChangedListener(this.hourTextWatcher);
        this.minuteEditText.removeTextChangedListener(this.minuteTextWatcher);
    }

    private void setTime(TimeModel time) {
        removeTextWatchers();
        Locale current = this.timePickerView.getResources().getConfiguration().locale;
        String minuteFormatted = String.format(current, TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(time.minute));
        String hourFormatted = String.format(current, TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(time.getHourForDisplay()));
        this.minuteTextInput.setText(minuteFormatted);
        this.hourTextInput.setText(hourFormatted);
        addTextWatchers();
        updateSelection();
    }

    private void setupPeriodToggle() {
        MaterialButtonToggleGroup materialButtonToggleGroup = (MaterialButtonToggleGroup) this.timePickerView.findViewById(R.id.material_clock_period_toggle);
        this.toggle = materialButtonToggleGroup;
        materialButtonToggleGroup.addOnButtonCheckedListener(new MaterialButtonToggleGroup.OnButtonCheckedListener() { // from class: com.google.android.material.timepicker.TimePickerTextInputPresenter.6
            @Override // com.google.android.material.button.MaterialButtonToggleGroup.OnButtonCheckedListener
            public void onButtonChecked(MaterialButtonToggleGroup group, int checkedId, boolean isChecked) {
                int period = checkedId == R.id.material_clock_period_pm_button ? 1 : 0;
                TimePickerTextInputPresenter.this.time.setPeriod(period);
            }
        });
        this.toggle.setVisibility(0);
        updateSelection();
    }

    private void updateSelection() {
        int i;
        MaterialButtonToggleGroup materialButtonToggleGroup = this.toggle;
        if (materialButtonToggleGroup == null) {
            return;
        }
        if (this.time.period == 0) {
            i = R.id.material_clock_period_am_button;
        } else {
            i = R.id.material_clock_period_pm_button;
        }
        materialButtonToggleGroup.check(i);
    }

    @Override // com.google.android.material.timepicker.TimePickerView.OnSelectionChange
    public void onSelectionChanged(int selection) {
        this.time.selection = selection;
        this.minuteTextInput.setChecked(selection == 12);
        this.hourTextInput.setChecked(selection == 10);
        updateSelection();
    }

    @Override // com.google.android.material.timepicker.TimePickerPresenter
    public void show() {
        this.timePickerView.setVisibility(0);
    }

    @Override // com.google.android.material.timepicker.TimePickerPresenter
    public void hide() {
        View currentFocus = this.timePickerView.getFocusedChild();
        if (currentFocus == null) {
            this.timePickerView.setVisibility(8);
            return;
        }
        Context context = this.timePickerView.getContext();
        InputMethodManager imm = (InputMethodManager) ContextCompat.getSystemService(context, InputMethodManager.class);
        if (imm != null) {
            imm.hideSoftInputFromWindow(currentFocus.getWindowToken(), 0);
        }
        this.timePickerView.setVisibility(8);
    }

    @Override // com.google.android.material.timepicker.TimePickerPresenter
    public void invalidate() {
        setTime(this.time);
    }

    private static void setCursorDrawableColor(EditText view, int color) {
        try {
            Context context = view.getContext();
            Field cursorDrawableResField = TextView.class.getDeclaredField("mCursorDrawableRes");
            cursorDrawableResField.setAccessible(true);
            int cursorDrawableResId = cursorDrawableResField.getInt(view);
            Field editorField = TextView.class.getDeclaredField("mEditor");
            editorField.setAccessible(true);
            Object editor = editorField.get(view);
            Class<?> clazz = editor.getClass();
            Field cursorDrawableField = clazz.getDeclaredField("mCursorDrawable");
            cursorDrawableField.setAccessible(true);
            Drawable drawable = AppCompatResources.getDrawable(context, cursorDrawableResId);
            drawable.setColorFilter(color, PorterDuff.Mode.SRC_IN);
            Drawable[] drawables = {drawable, drawable};
            cursorDrawableField.set(editor, drawables);
        } catch (Throwable th) {
        }
    }

    public void resetChecked() {
        this.minuteTextInput.setChecked(this.time.selection == 12);
        this.hourTextInput.setChecked(this.time.selection == 10);
    }

    public void clearCheck() {
        this.minuteTextInput.setChecked(false);
        this.hourTextInput.setChecked(false);
    }
}
