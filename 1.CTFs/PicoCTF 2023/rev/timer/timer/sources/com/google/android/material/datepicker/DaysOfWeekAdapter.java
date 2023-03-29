package com.google.android.material.datepicker;

import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import com.google.android.material.R;
import java.util.Calendar;
import java.util.Locale;
/* loaded from: classes.dex */
class DaysOfWeekAdapter extends BaseAdapter {
    private static final int CALENDAR_DAY_STYLE;
    private static final int NARROW_FORMAT = 4;
    private final Calendar calendar;
    private final int daysInWeek;
    private final int firstDayOfWeek;

    static {
        CALENDAR_DAY_STYLE = Build.VERSION.SDK_INT >= 26 ? 4 : 1;
    }

    public DaysOfWeekAdapter() {
        Calendar utcCalendar = UtcDates.getUtcCalendar();
        this.calendar = utcCalendar;
        this.daysInWeek = utcCalendar.getMaximum(7);
        this.firstDayOfWeek = utcCalendar.getFirstDayOfWeek();
    }

    @Override // android.widget.Adapter
    public Integer getItem(int position) {
        if (position >= this.daysInWeek) {
            return null;
        }
        return Integer.valueOf(positionToDayOfWeek(position));
    }

    @Override // android.widget.Adapter
    public long getItemId(int position) {
        return 0L;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.daysInWeek;
    }

    @Override // android.widget.Adapter
    public View getView(int position, View convertView, ViewGroup parent) {
        TextView dayOfWeek = (TextView) convertView;
        if (convertView == null) {
            LayoutInflater layoutInflater = LayoutInflater.from(parent.getContext());
            dayOfWeek = (TextView) layoutInflater.inflate(R.layout.mtrl_calendar_day_of_week, parent, false);
        }
        this.calendar.set(7, positionToDayOfWeek(position));
        Locale locale = dayOfWeek.getResources().getConfiguration().locale;
        dayOfWeek.setText(this.calendar.getDisplayName(7, CALENDAR_DAY_STYLE, locale));
        dayOfWeek.setContentDescription(String.format(parent.getContext().getString(R.string.mtrl_picker_day_of_week_column_header), this.calendar.getDisplayName(7, 2, Locale.getDefault())));
        return dayOfWeek;
    }

    private int positionToDayOfWeek(int position) {
        int dayConstant = this.firstDayOfWeek + position;
        int i = this.daysInWeek;
        if (dayConstant > i) {
            return dayConstant - i;
        }
        return dayConstant;
    }
}
