package androidx.constraintlayout.core;

import androidx.constraintlayout.core.LinearSystem;
import androidx.constraintlayout.core.SolverVariable;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class ArrayRow implements LinearSystem.Row {
    private static final boolean DEBUG = false;
    private static final boolean FULL_NEW_CHECK = false;
    public ArrayRowVariables variables;
    SolverVariable variable = null;
    float constantValue = 0.0f;
    boolean used = false;
    ArrayList<SolverVariable> variablesToUpdate = new ArrayList<>();
    boolean isSimpleDefinition = false;

    /* loaded from: classes.dex */
    public interface ArrayRowVariables {
        void add(SolverVariable solverVariable, float f, boolean z);

        void clear();

        boolean contains(SolverVariable solverVariable);

        void display();

        void divideByAmount(float f);

        float get(SolverVariable solverVariable);

        int getCurrentSize();

        SolverVariable getVariable(int i);

        float getVariableValue(int i);

        int indexOf(SolverVariable solverVariable);

        void invert();

        void put(SolverVariable solverVariable, float f);

        float remove(SolverVariable solverVariable, boolean z);

        int sizeInBytes();

        float use(ArrayRow arrayRow, boolean z);
    }

    public ArrayRow() {
    }

    public ArrayRow(Cache cache) {
        this.variables = new ArrayLinkedVariables(this, cache);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasKeyVariable() {
        SolverVariable solverVariable = this.variable;
        return solverVariable != null && (solverVariable.mType == SolverVariable.Type.UNRESTRICTED || this.constantValue >= 0.0f);
    }

    public String toString() {
        return toReadableString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String toReadableString() {
        String s = (this.variable == null ? "0" : "" + this.variable) + " = ";
        boolean addedVariable = false;
        if (this.constantValue != 0.0f) {
            s = s + this.constantValue;
            addedVariable = true;
        }
        int count = this.variables.getCurrentSize();
        for (int i = 0; i < count; i++) {
            SolverVariable v = this.variables.getVariable(i);
            if (v != null) {
                float amount = this.variables.getVariableValue(i);
                if (amount != 0.0f) {
                    String name = v.toString();
                    if (!addedVariable) {
                        if (amount < 0.0f) {
                            s = s + "- ";
                            amount *= -1.0f;
                        }
                    } else if (amount > 0.0f) {
                        s = s + " + ";
                    } else {
                        s = s + " - ";
                        amount *= -1.0f;
                    }
                    s = amount == 1.0f ? s + name : s + amount + " " + name;
                    addedVariable = true;
                }
            }
        }
        if (!addedVariable) {
            return s + "0.0";
        }
        return s;
    }

    public void reset() {
        this.variable = null;
        this.variables.clear();
        this.constantValue = 0.0f;
        this.isSimpleDefinition = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasVariable(SolverVariable v) {
        return this.variables.contains(v);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayRow createRowDefinition(SolverVariable variable, int value) {
        this.variable = variable;
        variable.computedValue = value;
        this.constantValue = value;
        this.isSimpleDefinition = true;
        return this;
    }

    public ArrayRow createRowEquals(SolverVariable variable, int value) {
        if (value < 0) {
            this.constantValue = value * (-1);
            this.variables.put(variable, 1.0f);
        } else {
            this.constantValue = value;
            this.variables.put(variable, -1.0f);
        }
        return this;
    }

    public ArrayRow createRowEquals(SolverVariable variableA, SolverVariable variableB, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = m;
        }
        if (!inverse) {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
        } else {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
        }
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayRow addSingleError(SolverVariable error, int sign) {
        this.variables.put(error, sign);
        return this;
    }

    public ArrayRow createRowGreaterThan(SolverVariable variableA, SolverVariable variableB, SolverVariable slack, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = m;
        }
        if (!inverse) {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.variables.put(slack, 1.0f);
        } else {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(slack, -1.0f);
        }
        return this;
    }

    public ArrayRow createRowGreaterThan(SolverVariable a, int b, SolverVariable slack) {
        this.constantValue = b;
        this.variables.put(a, -1.0f);
        return this;
    }

    public ArrayRow createRowLowerThan(SolverVariable variableA, SolverVariable variableB, SolverVariable slack, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = m;
        }
        if (!inverse) {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.variables.put(slack, -1.0f);
        } else {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(slack, 1.0f);
        }
        return this;
    }

    public ArrayRow createRowEqualMatchDimensions(float currentWeight, float totalWeights, float nextWeight, SolverVariable variableStartA, SolverVariable variableEndA, SolverVariable variableStartB, SolverVariable variableEndB) {
        this.constantValue = 0.0f;
        if (totalWeights == 0.0f || currentWeight == nextWeight) {
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, 1.0f);
            this.variables.put(variableStartB, -1.0f);
        } else if (currentWeight == 0.0f) {
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
        } else if (nextWeight == 0.0f) {
            this.variables.put(variableStartB, 1.0f);
            this.variables.put(variableEndB, -1.0f);
        } else {
            float cw = currentWeight / totalWeights;
            float nw = nextWeight / totalWeights;
            float w = cw / nw;
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, w);
            this.variables.put(variableStartB, -w);
        }
        return this;
    }

    public ArrayRow createRowEqualDimension(float currentWeight, float totalWeights, float nextWeight, SolverVariable variableStartA, int marginStartA, SolverVariable variableEndA, int marginEndA, SolverVariable variableStartB, int marginStartB, SolverVariable variableEndB, int marginEndB) {
        if (totalWeights == 0.0f || currentWeight == nextWeight) {
            this.constantValue = ((-marginStartA) - marginEndA) + marginStartB + marginEndB;
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, 1.0f);
            this.variables.put(variableStartB, -1.0f);
        } else {
            float cw = currentWeight / totalWeights;
            float nw = nextWeight / totalWeights;
            float w = cw / nw;
            this.constantValue = ((-marginStartA) - marginEndA) + (marginStartB * w) + (marginEndB * w);
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, w);
            this.variables.put(variableStartB, -w);
        }
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayRow createRowCentering(SolverVariable variableA, SolverVariable variableB, int marginA, float bias, SolverVariable variableC, SolverVariable variableD, int marginB) {
        if (variableB == variableC) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableD, 1.0f);
            this.variables.put(variableB, -2.0f);
            return this;
        }
        if (bias == 0.5f) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(variableC, -1.0f);
            this.variables.put(variableD, 1.0f);
            if (marginA > 0 || marginB > 0) {
                this.constantValue = (-marginA) + marginB;
            }
        } else if (bias <= 0.0f) {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.constantValue = marginA;
        } else if (bias < 1.0f) {
            this.variables.put(variableA, (1.0f - bias) * 1.0f);
            this.variables.put(variableB, (1.0f - bias) * (-1.0f));
            this.variables.put(variableC, (-1.0f) * bias);
            this.variables.put(variableD, bias * 1.0f);
            if (marginA > 0 || marginB > 0) {
                this.constantValue = ((-marginA) * (1.0f - bias)) + (marginB * bias);
            }
        } else {
            this.variables.put(variableD, -1.0f);
            this.variables.put(variableC, 1.0f);
            this.constantValue = -marginB;
        }
        return this;
    }

    public ArrayRow addError(LinearSystem system, int strength) {
        this.variables.put(system.createErrorVariable(strength, "ep"), 1.0f);
        this.variables.put(system.createErrorVariable(strength, "em"), -1.0f);
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayRow createRowDimensionPercent(SolverVariable variableA, SolverVariable variableC, float percent) {
        this.variables.put(variableA, -1.0f);
        this.variables.put(variableC, percent);
        return this;
    }

    public ArrayRow createRowDimensionRatio(SolverVariable variableA, SolverVariable variableB, SolverVariable variableC, SolverVariable variableD, float ratio) {
        this.variables.put(variableA, -1.0f);
        this.variables.put(variableB, 1.0f);
        this.variables.put(variableC, ratio);
        this.variables.put(variableD, -ratio);
        return this;
    }

    public ArrayRow createRowWithAngle(SolverVariable at, SolverVariable ab, SolverVariable bt, SolverVariable bb, float angleComponent) {
        this.variables.put(bt, 0.5f);
        this.variables.put(bb, 0.5f);
        this.variables.put(at, -0.5f);
        this.variables.put(ab, -0.5f);
        this.constantValue = -angleComponent;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int sizeInBytes() {
        int size = 0;
        if (this.variable != null) {
            size = 0 + 4;
        }
        return size + 4 + 4 + this.variables.sizeInBytes();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void ensurePositiveConstant() {
        float f = this.constantValue;
        if (f < 0.0f) {
            this.constantValue = f * (-1.0f);
            this.variables.invert();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean chooseSubject(LinearSystem system) {
        boolean addedExtra = false;
        SolverVariable pivotCandidate = chooseSubjectInVariables(system);
        if (pivotCandidate == null) {
            addedExtra = true;
        } else {
            pivot(pivotCandidate);
        }
        if (this.variables.getCurrentSize() == 0) {
            this.isSimpleDefinition = true;
        }
        return addedExtra;
    }

    SolverVariable chooseSubjectInVariables(LinearSystem system) {
        SolverVariable restrictedCandidate = null;
        SolverVariable unrestrictedCandidate = null;
        float unrestrictedCandidateAmount = 0.0f;
        float restrictedCandidateAmount = 0.0f;
        boolean unrestrictedCandidateIsNew = false;
        boolean restrictedCandidateIsNew = false;
        int currentSize = this.variables.getCurrentSize();
        for (int i = 0; i < currentSize; i++) {
            float amount = this.variables.getVariableValue(i);
            SolverVariable variable = this.variables.getVariable(i);
            if (variable.mType == SolverVariable.Type.UNRESTRICTED) {
                if (unrestrictedCandidate == null) {
                    unrestrictedCandidate = variable;
                    unrestrictedCandidateAmount = amount;
                    unrestrictedCandidateIsNew = isNew(variable, system);
                } else if (unrestrictedCandidateAmount > amount) {
                    unrestrictedCandidate = variable;
                    unrestrictedCandidateAmount = amount;
                    unrestrictedCandidateIsNew = isNew(variable, system);
                } else if (!unrestrictedCandidateIsNew && isNew(variable, system)) {
                    unrestrictedCandidate = variable;
                    unrestrictedCandidateAmount = amount;
                    unrestrictedCandidateIsNew = true;
                }
            } else if (unrestrictedCandidate == null && amount < 0.0f) {
                if (restrictedCandidate == null) {
                    restrictedCandidate = variable;
                    restrictedCandidateAmount = amount;
                    restrictedCandidateIsNew = isNew(variable, system);
                } else if (restrictedCandidateAmount > amount) {
                    restrictedCandidate = variable;
                    restrictedCandidateAmount = amount;
                    restrictedCandidateIsNew = isNew(variable, system);
                } else if (!restrictedCandidateIsNew && isNew(variable, system)) {
                    restrictedCandidate = variable;
                    restrictedCandidateAmount = amount;
                    restrictedCandidateIsNew = true;
                }
            }
        }
        if (unrestrictedCandidate != null) {
            return unrestrictedCandidate;
        }
        return restrictedCandidate;
    }

    private boolean isNew(SolverVariable variable, LinearSystem system) {
        return variable.usageInRowCount <= 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void pivot(SolverVariable v) {
        SolverVariable solverVariable = this.variable;
        if (solverVariable != null) {
            this.variables.put(solverVariable, -1.0f);
            this.variable.definitionId = -1;
            this.variable = null;
        }
        float amount = this.variables.remove(v, true) * (-1.0f);
        this.variable = v;
        if (amount == 1.0f) {
            return;
        }
        this.constantValue /= amount;
        this.variables.divideByAmount(amount);
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public boolean isEmpty() {
        return this.variable == null && this.constantValue == 0.0f && this.variables.getCurrentSize() == 0;
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void updateFromRow(LinearSystem system, ArrayRow definition, boolean removeFromDefinition) {
        float value = this.variables.use(definition, removeFromDefinition);
        this.constantValue += definition.constantValue * value;
        if (removeFromDefinition) {
            definition.variable.removeFromRow(this);
        }
        if (LinearSystem.SIMPLIFY_SYNONYMS && this.variable != null && this.variables.getCurrentSize() == 0) {
            this.isSimpleDefinition = true;
            system.hasSimpleDefinition = true;
        }
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void updateFromFinalVariable(LinearSystem system, SolverVariable variable, boolean removeFromDefinition) {
        if (variable == null || !variable.isFinalValue) {
            return;
        }
        float value = this.variables.get(variable);
        this.constantValue += variable.computedValue * value;
        this.variables.remove(variable, removeFromDefinition);
        if (removeFromDefinition) {
            variable.removeFromRow(this);
        }
        if (LinearSystem.SIMPLIFY_SYNONYMS && this.variables.getCurrentSize() == 0) {
            this.isSimpleDefinition = true;
            system.hasSimpleDefinition = true;
        }
    }

    public void updateFromSynonymVariable(LinearSystem system, SolverVariable variable, boolean removeFromDefinition) {
        if (variable == null || !variable.isSynonym) {
            return;
        }
        float value = this.variables.get(variable);
        this.constantValue += variable.synonymDelta * value;
        this.variables.remove(variable, removeFromDefinition);
        if (removeFromDefinition) {
            variable.removeFromRow(this);
        }
        this.variables.add(system.mCache.mIndexedVariables[variable.synonym], value, removeFromDefinition);
        if (LinearSystem.SIMPLIFY_SYNONYMS && this.variables.getCurrentSize() == 0) {
            this.isSimpleDefinition = true;
            system.hasSimpleDefinition = true;
        }
    }

    private SolverVariable pickPivotInVariables(boolean[] avoid, SolverVariable exclude) {
        float value = 0.0f;
        SolverVariable pivot = null;
        SolverVariable pivotSlack = null;
        float valueSlack = 0.0f;
        int currentSize = this.variables.getCurrentSize();
        for (int i = 0; i < currentSize; i++) {
            float currentValue = this.variables.getVariableValue(i);
            if (currentValue < 0.0f) {
                SolverVariable v = this.variables.getVariable(i);
                if ((avoid == null || !avoid[v.id]) && v != exclude) {
                    if (1 != 0) {
                        if ((v.mType == SolverVariable.Type.SLACK || v.mType == SolverVariable.Type.ERROR) && currentValue < value) {
                            value = currentValue;
                            pivot = v;
                        }
                    } else if (v.mType == SolverVariable.Type.SLACK) {
                        if (currentValue < valueSlack) {
                            valueSlack = currentValue;
                            pivotSlack = v;
                        }
                    } else if (v.mType == SolverVariable.Type.ERROR && currentValue < value) {
                        value = currentValue;
                        pivot = v;
                    }
                }
            }
        }
        if (1 != 0) {
            return pivot;
        }
        return pivot != null ? pivot : pivotSlack;
    }

    public SolverVariable pickPivot(SolverVariable exclude) {
        return pickPivotInVariables(null, exclude);
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public SolverVariable getPivotCandidate(LinearSystem system, boolean[] avoid) {
        return pickPivotInVariables(avoid, null);
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void clear() {
        this.variables.clear();
        this.variable = null;
        this.constantValue = 0.0f;
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void initFromRow(LinearSystem.Row row) {
        if (row instanceof ArrayRow) {
            ArrayRow copiedRow = (ArrayRow) row;
            this.variable = null;
            this.variables.clear();
            for (int i = 0; i < copiedRow.variables.getCurrentSize(); i++) {
                SolverVariable var = copiedRow.variables.getVariable(i);
                float val = copiedRow.variables.getVariableValue(i);
                this.variables.add(var, val, true);
            }
        }
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void addError(SolverVariable error) {
        float weight = 1.0f;
        if (error.strength == 1) {
            weight = 1.0f;
        } else if (error.strength == 2) {
            weight = 1000.0f;
        } else if (error.strength == 3) {
            weight = 1000000.0f;
        } else if (error.strength == 4) {
            weight = 1.0E9f;
        } else if (error.strength == 5) {
            weight = 1.0E12f;
        }
        this.variables.put(error, weight);
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public SolverVariable getKey() {
        return this.variable;
    }

    @Override // androidx.constraintlayout.core.LinearSystem.Row
    public void updateFromSystem(LinearSystem system) {
        if (system.mRows.length == 0) {
            return;
        }
        boolean done = false;
        while (!done) {
            int currentSize = this.variables.getCurrentSize();
            for (int i = 0; i < currentSize; i++) {
                SolverVariable variable = this.variables.getVariable(i);
                if (variable.definitionId != -1 || variable.isFinalValue || variable.isSynonym) {
                    this.variablesToUpdate.add(variable);
                }
            }
            int size = this.variablesToUpdate.size();
            if (size > 0) {
                for (int i2 = 0; i2 < size; i2++) {
                    SolverVariable variable2 = this.variablesToUpdate.get(i2);
                    if (variable2.isFinalValue) {
                        updateFromFinalVariable(system, variable2, true);
                    } else if (!variable2.isSynonym) {
                        updateFromRow(system, system.mRows[variable2.definitionId], true);
                    } else {
                        updateFromSynonymVariable(system, variable2, true);
                    }
                }
                this.variablesToUpdate.clear();
            } else {
                done = true;
            }
        }
        if (LinearSystem.SIMPLIFY_SYNONYMS && this.variable != null && this.variables.getCurrentSize() == 0) {
            this.isSimpleDefinition = true;
            system.hasSimpleDefinition = true;
        }
    }
}
