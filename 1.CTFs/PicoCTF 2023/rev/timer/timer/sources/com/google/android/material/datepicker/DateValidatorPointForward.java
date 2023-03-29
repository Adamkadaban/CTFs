package com.google.android.material.datepicker;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.material.datepicker.CalendarConstraints;
import java.util.Arrays;
/* loaded from: classes.dex */
public class DateValidatorPointForward implements CalendarConstraints.DateValidator {
    public static final Parcelable.Creator<DateValidatorPointForward> CREATOR = new Parcelable.Creator<DateValidatorPointForward>() { // from class: com.google.android.material.datepicker.DateValidatorPointForward.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DateValidatorPointForward createFromParcel(Parcel source) {
            return new DateValidatorPointForward(source.readLong());
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DateValidatorPointForward[] newArray(int size) {
            return new DateValidatorPointForward[size];
        }
    };
    private final long point;

    private DateValidatorPointForward(long point) {
        this.point = point;
    }

    public static DateValidatorPointForward from(long point) {
        return new DateValidatorPointForward(point);
    }

    public static DateValidatorPointForward now() {
        return from(UtcDates.getTodayCalendar().getTimeInMillis());
    }

    @Override // com.google.android.material.datepicker.CalendarConstraints.DateValidator
    public boolean isValid(long date) {
        return date >= this.point;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(this.point);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof DateValidatorPointForward) {
            DateValidatorPointForward that = (DateValidatorPointForward) o;
            return this.point == that.point;
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {Long.valueOf(this.point)};
        return Arrays.hashCode(hashedFields);
    }
}
