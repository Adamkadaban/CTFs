package com.google.android.material.datepicker;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.core.util.Preconditions;
import com.google.android.material.datepicker.CalendarConstraints;
import java.util.List;
/* loaded from: classes.dex */
public final class CompositeDateValidator implements CalendarConstraints.DateValidator {
    private static final int COMPARATOR_ALL_ID = 2;
    private static final int COMPARATOR_ANY_ID = 1;
    private final Operator operator;
    private final List<CalendarConstraints.DateValidator> validators;
    private static final Operator ANY_OPERATOR = new Operator() { // from class: com.google.android.material.datepicker.CompositeDateValidator.1
        @Override // com.google.android.material.datepicker.CompositeDateValidator.Operator
        public boolean isValid(List<CalendarConstraints.DateValidator> validators, long date) {
            for (CalendarConstraints.DateValidator validator : validators) {
                if (validator != null && validator.isValid(date)) {
                    return true;
                }
            }
            return false;
        }

        @Override // com.google.android.material.datepicker.CompositeDateValidator.Operator
        public int getId() {
            return 1;
        }
    };
    private static final Operator ALL_OPERATOR = new Operator() { // from class: com.google.android.material.datepicker.CompositeDateValidator.2
        @Override // com.google.android.material.datepicker.CompositeDateValidator.Operator
        public boolean isValid(List<CalendarConstraints.DateValidator> validators, long date) {
            for (CalendarConstraints.DateValidator validator : validators) {
                if (validator != null && !validator.isValid(date)) {
                    return false;
                }
            }
            return true;
        }

        @Override // com.google.android.material.datepicker.CompositeDateValidator.Operator
        public int getId() {
            return 2;
        }
    };
    public static final Parcelable.Creator<CompositeDateValidator> CREATOR = new Parcelable.Creator<CompositeDateValidator>() { // from class: com.google.android.material.datepicker.CompositeDateValidator.3
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CompositeDateValidator createFromParcel(Parcel source) {
            Operator operator;
            List<CalendarConstraints.DateValidator> validators = source.readArrayList(CalendarConstraints.DateValidator.class.getClassLoader());
            int id = source.readInt();
            if (id == 2) {
                operator = CompositeDateValidator.ALL_OPERATOR;
            } else {
                operator = id == 1 ? CompositeDateValidator.ANY_OPERATOR : CompositeDateValidator.ALL_OPERATOR;
            }
            return new CompositeDateValidator((List) Preconditions.checkNotNull(validators), operator);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CompositeDateValidator[] newArray(int size) {
            return new CompositeDateValidator[size];
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface Operator {
        int getId();

        boolean isValid(List<CalendarConstraints.DateValidator> list, long j);
    }

    private CompositeDateValidator(List<CalendarConstraints.DateValidator> validators, Operator operator) {
        this.validators = validators;
        this.operator = operator;
    }

    public static CalendarConstraints.DateValidator allOf(List<CalendarConstraints.DateValidator> validators) {
        return new CompositeDateValidator(validators, ALL_OPERATOR);
    }

    public static CalendarConstraints.DateValidator anyOf(List<CalendarConstraints.DateValidator> validators) {
        return new CompositeDateValidator(validators, ANY_OPERATOR);
    }

    @Override // com.google.android.material.datepicker.CalendarConstraints.DateValidator
    public boolean isValid(long date) {
        return this.operator.isValid(this.validators, date);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeList(this.validators);
        dest.writeInt(this.operator.getId());
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof CompositeDateValidator) {
            CompositeDateValidator that = (CompositeDateValidator) o;
            return this.validators.equals(that.validators) && this.operator.getId() == that.operator.getId();
        }
        return false;
    }

    public int hashCode() {
        return this.validators.hashCode();
    }
}
