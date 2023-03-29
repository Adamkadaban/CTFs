package androidx.constraintlayout.core;
/* loaded from: classes.dex */
public class GoalRow extends ArrayRow {
    public GoalRow(Cache cache) {
        super(cache);
    }

    @Override // androidx.constraintlayout.core.ArrayRow, androidx.constraintlayout.core.LinearSystem.Row
    public void addError(SolverVariable error) {
        super.addError(error);
        error.usageInRowCount--;
    }
}
