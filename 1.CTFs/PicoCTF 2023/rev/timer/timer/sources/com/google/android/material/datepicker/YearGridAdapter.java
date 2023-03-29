package com.google.android.material.datepicker;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.R;
import com.google.android.material.datepicker.MaterialCalendar;
import com.google.android.material.timepicker.TimeModel;
import java.util.Calendar;
import java.util.Locale;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class YearGridAdapter extends RecyclerView.Adapter<ViewHolder> {
    private final MaterialCalendar<?> materialCalendar;

    /* loaded from: classes.dex */
    public static class ViewHolder extends RecyclerView.ViewHolder {
        final TextView textView;

        ViewHolder(TextView view) {
            super(view);
            this.textView = view;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public YearGridAdapter(MaterialCalendar<?> materialCalendar) {
        this.materialCalendar = materialCalendar;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
        TextView yearTextView = (TextView) LayoutInflater.from(viewGroup.getContext()).inflate(R.layout.mtrl_calendar_year, viewGroup, false);
        return new ViewHolder(yearTextView);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(ViewHolder viewHolder, int position) {
        int year = getYearForPosition(position);
        String navigateYear = viewHolder.textView.getContext().getString(R.string.mtrl_picker_navigate_to_year_description);
        viewHolder.textView.setText(String.format(Locale.getDefault(), TimeModel.NUMBER_FORMAT, Integer.valueOf(year)));
        viewHolder.textView.setContentDescription(String.format(navigateYear, Integer.valueOf(year)));
        CalendarStyle styles = this.materialCalendar.getCalendarStyle();
        Calendar calendar = UtcDates.getTodayCalendar();
        CalendarItemStyle style = calendar.get(1) == year ? styles.todayYear : styles.year;
        for (Long day : this.materialCalendar.getDateSelector().getSelectedDays()) {
            calendar.setTimeInMillis(day.longValue());
            if (calendar.get(1) == year) {
                style = styles.selectedYear;
            }
        }
        style.styleItem(viewHolder.textView);
        viewHolder.textView.setOnClickListener(createYearClickListener(year));
    }

    private View.OnClickListener createYearClickListener(final int year) {
        return new View.OnClickListener() { // from class: com.google.android.material.datepicker.YearGridAdapter.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                Month current = Month.create(year, YearGridAdapter.this.materialCalendar.getCurrentMonth().month);
                CalendarConstraints calendarConstraints = YearGridAdapter.this.materialCalendar.getCalendarConstraints();
                Month moveTo = calendarConstraints.clamp(current);
                YearGridAdapter.this.materialCalendar.setCurrentMonth(moveTo);
                YearGridAdapter.this.materialCalendar.setSelector(MaterialCalendar.CalendarSelector.DAY);
            }
        };
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.materialCalendar.getCalendarConstraints().getYearSpan();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getPositionForYear(int year) {
        return year - this.materialCalendar.getCalendarConstraints().getStart().year;
    }

    int getYearForPosition(int position) {
        return this.materialCalendar.getCalendarConstraints().getStart().year + position;
    }
}
