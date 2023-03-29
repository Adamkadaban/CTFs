package com.google.android.material.datepicker;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import com.google.android.material.R;
import com.google.android.material.timepicker.TimeModel;
import java.util.Collection;
import java.util.Locale;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class MonthAdapter extends BaseAdapter {
    static final int MAXIMUM_WEEKS = UtcDates.getUtcCalendar().getMaximum(4);
    final CalendarConstraints calendarConstraints;
    CalendarStyle calendarStyle;
    final DateSelector<?> dateSelector;
    final Month month;
    private Collection<Long> previouslySelectedDates;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MonthAdapter(Month month, DateSelector<?> dateSelector, CalendarConstraints calendarConstraints) {
        this.month = month;
        this.dateSelector = dateSelector;
        this.calendarConstraints = calendarConstraints;
        this.previouslySelectedDates = dateSelector.getSelectedDays();
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public boolean hasStableIds() {
        return true;
    }

    @Override // android.widget.Adapter
    public Long getItem(int position) {
        if (position < this.month.daysFromStartOfWeekToFirstOfMonth() || position > lastPositionInMonth()) {
            return null;
        }
        return Long.valueOf(this.month.getDay(positionToDay(position)));
    }

    @Override // android.widget.Adapter
    public long getItemId(int position) {
        return position / this.month.daysInWeek;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.month.daysInMonth + firstPositionInMonth();
    }

    @Override // android.widget.Adapter
    public TextView getView(int position, View convertView, ViewGroup parent) {
        initializeStyles(parent.getContext());
        TextView day = (TextView) convertView;
        if (convertView == null) {
            LayoutInflater layoutInflater = LayoutInflater.from(parent.getContext());
            day = (TextView) layoutInflater.inflate(R.layout.mtrl_calendar_day, parent, false);
        }
        int offsetPosition = position - firstPositionInMonth();
        if (offsetPosition < 0 || offsetPosition >= this.month.daysInMonth) {
            day.setVisibility(8);
            day.setEnabled(false);
        } else {
            int dayNumber = offsetPosition + 1;
            day.setTag(this.month);
            Locale locale = day.getResources().getConfiguration().locale;
            day.setText(String.format(locale, TimeModel.NUMBER_FORMAT, Integer.valueOf(dayNumber)));
            long dayInMillis = this.month.getDay(dayNumber);
            if (this.month.year == Month.current().year) {
                day.setContentDescription(DateStrings.getMonthDayOfWeekDay(dayInMillis));
            } else {
                day.setContentDescription(DateStrings.getYearMonthDayOfWeekDay(dayInMillis));
            }
            day.setVisibility(0);
            day.setEnabled(true);
        }
        Long date = getItem(position);
        if (date == null) {
            return day;
        }
        updateSelectedState(day, date.longValue());
        return day;
    }

    public void updateSelectedStates(MaterialCalendarGridView monthGrid) {
        for (Long date : this.previouslySelectedDates) {
            updateSelectedStateForDate(monthGrid, date.longValue());
        }
        DateSelector<?> dateSelector = this.dateSelector;
        if (dateSelector != null) {
            for (Long date2 : dateSelector.getSelectedDays()) {
                updateSelectedStateForDate(monthGrid, date2.longValue());
            }
            this.previouslySelectedDates = this.dateSelector.getSelectedDays();
        }
    }

    private void updateSelectedStateForDate(MaterialCalendarGridView monthGrid, long date) {
        if (Month.create(date).equals(this.month)) {
            int day = this.month.getDayOfMonth(date);
            updateSelectedState((TextView) monthGrid.getChildAt(monthGrid.getAdapter2().dayToPosition(day) - monthGrid.getFirstVisiblePosition()), date);
        }
    }

    private void updateSelectedState(TextView day, long date) {
        CalendarItemStyle style;
        if (day == null) {
            return;
        }
        if (this.calendarConstraints.getDateValidator().isValid(date)) {
            day.setEnabled(true);
            if (isSelected(date)) {
                style = this.calendarStyle.selectedDay;
            } else if (UtcDates.getTodayCalendar().getTimeInMillis() == date) {
                style = this.calendarStyle.todayDay;
            } else {
                style = this.calendarStyle.day;
            }
        } else {
            day.setEnabled(false);
            style = this.calendarStyle.invalidDay;
        }
        style.styleItem(day);
    }

    private boolean isSelected(long date) {
        for (Long l : this.dateSelector.getSelectedDays()) {
            long selectedDay = l.longValue();
            if (UtcDates.canonicalYearMonthDay(date) == UtcDates.canonicalYearMonthDay(selectedDay)) {
                return true;
            }
        }
        return false;
    }

    private void initializeStyles(Context context) {
        if (this.calendarStyle == null) {
            this.calendarStyle = new CalendarStyle(context);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int firstPositionInMonth() {
        return this.month.daysFromStartOfWeekToFirstOfMonth();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int lastPositionInMonth() {
        return (this.month.daysFromStartOfWeekToFirstOfMonth() + this.month.daysInMonth) - 1;
    }

    int positionToDay(int position) {
        return (position - this.month.daysFromStartOfWeekToFirstOfMonth()) + 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int dayToPosition(int day) {
        int offsetFromFirst = day - 1;
        return firstPositionInMonth() + offsetFromFirst;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean withinMonth(int position) {
        return position >= firstPositionInMonth() && position <= lastPositionInMonth();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isFirstInRow(int position) {
        return position % this.month.daysInWeek == 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isLastInRow(int position) {
        return (position + 1) % this.month.daysInWeek == 0;
    }
}
