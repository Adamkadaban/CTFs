package com.google.android.material.datepicker;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.core.util.ObjectsCompat;
import java.util.Arrays;
/* loaded from: classes.dex */
public final class CalendarConstraints implements Parcelable {
    public static final Parcelable.Creator<CalendarConstraints> CREATOR = new Parcelable.Creator<CalendarConstraints>() { // from class: com.google.android.material.datepicker.CalendarConstraints.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CalendarConstraints createFromParcel(Parcel source) {
            Month start = (Month) source.readParcelable(Month.class.getClassLoader());
            Month end = (Month) source.readParcelable(Month.class.getClassLoader());
            Month openAt = (Month) source.readParcelable(Month.class.getClassLoader());
            DateValidator validator = (DateValidator) source.readParcelable(DateValidator.class.getClassLoader());
            return new CalendarConstraints(start, end, validator, openAt);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CalendarConstraints[] newArray(int size) {
            return new CalendarConstraints[size];
        }
    };
    private final Month end;
    private final int monthSpan;
    private Month openAt;
    private final Month start;
    private final DateValidator validator;
    private final int yearSpan;

    /* loaded from: classes.dex */
    public interface DateValidator extends Parcelable {
        boolean isValid(long j);
    }

    private CalendarConstraints(Month start, Month end, DateValidator validator, Month openAt) {
        this.start = start;
        this.end = end;
        this.openAt = openAt;
        this.validator = validator;
        if (openAt != null && start.compareTo(openAt) > 0) {
            throw new IllegalArgumentException("start Month cannot be after current Month");
        }
        if (openAt != null && openAt.compareTo(end) > 0) {
            throw new IllegalArgumentException("current Month cannot be after end Month");
        }
        this.monthSpan = start.monthsUntil(end) + 1;
        this.yearSpan = (end.year - start.year) + 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isWithinBounds(long date) {
        if (this.start.getDay(1) <= date) {
            Month month = this.end;
            if (date <= month.getDay(month.daysInMonth)) {
                return true;
            }
        }
        return false;
    }

    public DateValidator getDateValidator() {
        return this.validator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Month getStart() {
        return this.start;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Month getEnd() {
        return this.end;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Month getOpenAt() {
        return this.openAt;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setOpenAt(Month openAt) {
        this.openAt = openAt;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getMonthSpan() {
        return this.monthSpan;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getYearSpan() {
        return this.yearSpan;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof CalendarConstraints) {
            CalendarConstraints that = (CalendarConstraints) o;
            return this.start.equals(that.start) && this.end.equals(that.end) && ObjectsCompat.equals(this.openAt, that.openAt) && this.validator.equals(that.validator);
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {this.start, this.end, this.openAt, this.validator};
        return Arrays.hashCode(hashedFields);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeParcelable(this.start, 0);
        dest.writeParcelable(this.end, 0);
        dest.writeParcelable(this.openAt, 0);
        dest.writeParcelable(this.validator, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Month clamp(Month month) {
        if (month.compareTo(this.start) < 0) {
            return this.start;
        }
        if (month.compareTo(this.end) > 0) {
            return this.end;
        }
        return month;
    }

    /* loaded from: classes.dex */
    public static final class Builder {
        private static final String DEEP_COPY_VALIDATOR_KEY = "DEEP_COPY_VALIDATOR_KEY";
        private long end;
        private Long openAt;
        private long start;
        private DateValidator validator;
        static final long DEFAULT_START = UtcDates.canonicalYearMonthDay(Month.create(1900, 0).timeInMillis);
        static final long DEFAULT_END = UtcDates.canonicalYearMonthDay(Month.create(2100, 11).timeInMillis);

        public Builder() {
            this.start = DEFAULT_START;
            this.end = DEFAULT_END;
            this.validator = DateValidatorPointForward.from(Long.MIN_VALUE);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder(CalendarConstraints clone) {
            this.start = DEFAULT_START;
            this.end = DEFAULT_END;
            this.validator = DateValidatorPointForward.from(Long.MIN_VALUE);
            this.start = clone.start.timeInMillis;
            this.end = clone.end.timeInMillis;
            this.openAt = Long.valueOf(clone.openAt.timeInMillis);
            this.validator = clone.validator;
        }

        public Builder setStart(long month) {
            this.start = month;
            return this;
        }

        public Builder setEnd(long month) {
            this.end = month;
            return this;
        }

        public Builder setOpenAt(long month) {
            this.openAt = Long.valueOf(month);
            return this;
        }

        public Builder setValidator(DateValidator validator) {
            this.validator = validator;
            return this;
        }

        public CalendarConstraints build() {
            Bundle deepCopyBundle = new Bundle();
            deepCopyBundle.putParcelable(DEEP_COPY_VALIDATOR_KEY, this.validator);
            Month create = Month.create(this.start);
            Month create2 = Month.create(this.end);
            DateValidator dateValidator = (DateValidator) deepCopyBundle.getParcelable(DEEP_COPY_VALIDATOR_KEY);
            Long l = this.openAt;
            return new CalendarConstraints(create, create2, dateValidator, l == null ? null : Month.create(l.longValue()));
        }
    }
}
