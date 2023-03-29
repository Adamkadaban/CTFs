package androidx.constraintlayout.core;

import androidx.constraintlayout.core.SolverVariable;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
/* loaded from: classes.dex */
public class LinearSystem {
    public static final boolean DEBUG = false;
    private static final boolean DEBUG_CONSTRAINTS = false;
    public static final boolean FULL_DEBUG = false;
    public static final boolean MEASURE = false;
    public static Metrics sMetrics;
    final Cache mCache;
    private Row mGoal;
    ArrayRow[] mRows;
    private Row mTempGoal;
    public static boolean USE_DEPENDENCY_ORDERING = false;
    public static boolean USE_BASIC_SYNONYMS = true;
    public static boolean SIMPLIFY_SYNONYMS = true;
    public static boolean USE_SYNONYMS = true;
    public static boolean SKIP_COLUMNS = true;
    public static boolean OPTIMIZED_ENGINE = false;
    private static int POOL_SIZE = 1000;
    public static long ARRAY_ROW_CREATION = 0;
    public static long OPTIMIZED_ARRAY_ROW_CREATION = 0;
    public boolean hasSimpleDefinition = false;
    int mVariablesID = 0;
    private HashMap<String, SolverVariable> mVariables = null;
    private int TABLE_SIZE = 32;
    private int mMaxColumns = 32;
    public boolean graphOptimizer = false;
    public boolean newgraphOptimizer = false;
    private boolean[] mAlreadyTestedCandidates = new boolean[32];
    int mNumColumns = 1;
    int mNumRows = 0;
    private int mMaxRows = 32;
    private SolverVariable[] mPoolVariables = new SolverVariable[POOL_SIZE];
    private int mPoolVariablesCount = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface Row {
        void addError(SolverVariable solverVariable);

        void clear();

        SolverVariable getKey();

        SolverVariable getPivotCandidate(LinearSystem linearSystem, boolean[] zArr);

        void initFromRow(Row row);

        boolean isEmpty();

        void updateFromFinalVariable(LinearSystem linearSystem, SolverVariable solverVariable, boolean z);

        void updateFromRow(LinearSystem linearSystem, ArrayRow arrayRow, boolean z);

        void updateFromSystem(LinearSystem linearSystem);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class ValuesRow extends ArrayRow {
        public ValuesRow(Cache cache) {
            this.variables = new SolverVariableValues(this, cache);
        }
    }

    public LinearSystem() {
        this.mRows = null;
        this.mRows = new ArrayRow[32];
        releaseRows();
        Cache cache = new Cache();
        this.mCache = cache;
        this.mGoal = new PriorityGoalRow(cache);
        if (OPTIMIZED_ENGINE) {
            this.mTempGoal = new ValuesRow(cache);
        } else {
            this.mTempGoal = new ArrayRow(cache);
        }
    }

    public void fillMetrics(Metrics metrics) {
        sMetrics = metrics;
    }

    public static Metrics getMetrics() {
        return sMetrics;
    }

    private void increaseTableSize() {
        int i = this.TABLE_SIZE * 2;
        this.TABLE_SIZE = i;
        this.mRows = (ArrayRow[]) Arrays.copyOf(this.mRows, i);
        Cache cache = this.mCache;
        cache.mIndexedVariables = (SolverVariable[]) Arrays.copyOf(cache.mIndexedVariables, this.TABLE_SIZE);
        int i2 = this.TABLE_SIZE;
        this.mAlreadyTestedCandidates = new boolean[i2];
        this.mMaxColumns = i2;
        this.mMaxRows = i2;
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.tableSizeIncrease++;
            Metrics metrics2 = sMetrics;
            metrics2.maxTableSize = Math.max(metrics2.maxTableSize, this.TABLE_SIZE);
            Metrics metrics3 = sMetrics;
            metrics3.lastTableSize = metrics3.maxTableSize;
        }
    }

    private void releaseRows() {
        if (OPTIMIZED_ENGINE) {
            for (int i = 0; i < this.mNumRows; i++) {
                ArrayRow row = this.mRows[i];
                if (row != null) {
                    this.mCache.optimizedArrayRowPool.release(row);
                }
                this.mRows[i] = null;
            }
            return;
        }
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            ArrayRow row2 = this.mRows[i2];
            if (row2 != null) {
                this.mCache.arrayRowPool.release(row2);
            }
            this.mRows[i2] = null;
        }
    }

    public void reset() {
        for (int i = 0; i < this.mCache.mIndexedVariables.length; i++) {
            SolverVariable variable = this.mCache.mIndexedVariables[i];
            if (variable != null) {
                variable.reset();
            }
        }
        this.mCache.solverVariablePool.releaseAll(this.mPoolVariables, this.mPoolVariablesCount);
        this.mPoolVariablesCount = 0;
        Arrays.fill(this.mCache.mIndexedVariables, (Object) null);
        HashMap<String, SolverVariable> hashMap = this.mVariables;
        if (hashMap != null) {
            hashMap.clear();
        }
        this.mVariablesID = 0;
        this.mGoal.clear();
        this.mNumColumns = 1;
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            ArrayRow[] arrayRowArr = this.mRows;
            if (arrayRowArr[i2] != null) {
                arrayRowArr[i2].used = false;
            }
        }
        releaseRows();
        this.mNumRows = 0;
        if (OPTIMIZED_ENGINE) {
            this.mTempGoal = new ValuesRow(this.mCache);
        } else {
            this.mTempGoal = new ArrayRow(this.mCache);
        }
    }

    public SolverVariable createObjectVariable(Object anchor) {
        if (anchor == null) {
            return null;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = null;
        if (anchor instanceof ConstraintAnchor) {
            variable = ((ConstraintAnchor) anchor).getSolverVariable();
            if (variable == null) {
                ((ConstraintAnchor) anchor).resetSolverVariable(this.mCache);
                variable = ((ConstraintAnchor) anchor).getSolverVariable();
            }
            if (variable.id == -1 || variable.id > this.mVariablesID || this.mCache.mIndexedVariables[variable.id] == null) {
                if (variable.id != -1) {
                    variable.reset();
                }
                int i = this.mVariablesID + 1;
                this.mVariablesID = i;
                this.mNumColumns++;
                variable.id = i;
                variable.mType = SolverVariable.Type.UNRESTRICTED;
                this.mCache.mIndexedVariables[this.mVariablesID] = variable;
            }
        }
        return variable;
    }

    public ArrayRow createRow() {
        ArrayRow row;
        if (OPTIMIZED_ENGINE) {
            row = this.mCache.optimizedArrayRowPool.acquire();
            if (row == null) {
                row = new ValuesRow(this.mCache);
                OPTIMIZED_ARRAY_ROW_CREATION++;
            } else {
                row.reset();
            }
        } else {
            row = this.mCache.arrayRowPool.acquire();
            if (row == null) {
                row = new ArrayRow(this.mCache);
                ARRAY_ROW_CREATION++;
            } else {
                row.reset();
            }
        }
        SolverVariable.increaseErrorId();
        return row;
    }

    public SolverVariable createSlackVariable() {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.slackvariables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.SLACK, null);
        int i = this.mVariablesID + 1;
        this.mVariablesID = i;
        this.mNumColumns++;
        variable.id = i;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    public SolverVariable createExtraVariable() {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.extravariables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.SLACK, null);
        int i = this.mVariablesID + 1;
        this.mVariablesID = i;
        this.mNumColumns++;
        variable.id = i;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    private void addError(ArrayRow row) {
        row.addError(this, 0);
    }

    private void addSingleError(ArrayRow row, int sign) {
        addSingleError(row, sign, 0);
    }

    void addSingleError(ArrayRow row, int sign, int strength) {
        SolverVariable error = createErrorVariable(strength, null);
        row.addSingleError(error, sign);
    }

    private SolverVariable createVariable(String name, SolverVariable.Type type) {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.variables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(type, null);
        variable.setName(name);
        int i = this.mVariablesID + 1;
        this.mVariablesID = i;
        this.mNumColumns++;
        variable.id = i;
        if (this.mVariables == null) {
            this.mVariables = new HashMap<>();
        }
        this.mVariables.put(name, variable);
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    public SolverVariable createErrorVariable(int strength, String prefix) {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.errors++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.ERROR, prefix);
        int i = this.mVariablesID + 1;
        this.mVariablesID = i;
        this.mNumColumns++;
        variable.id = i;
        variable.strength = strength;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        this.mGoal.addError(variable);
        return variable;
    }

    private SolverVariable acquireSolverVariable(SolverVariable.Type type, String prefix) {
        SolverVariable variable = this.mCache.solverVariablePool.acquire();
        if (variable == null) {
            variable = new SolverVariable(type, prefix);
            variable.setType(type, prefix);
        } else {
            variable.reset();
            variable.setType(type, prefix);
        }
        int i = this.mPoolVariablesCount;
        int i2 = POOL_SIZE;
        if (i >= i2) {
            int i3 = i2 * 2;
            POOL_SIZE = i3;
            this.mPoolVariables = (SolverVariable[]) Arrays.copyOf(this.mPoolVariables, i3);
        }
        SolverVariable[] solverVariableArr = this.mPoolVariables;
        int i4 = this.mPoolVariablesCount;
        this.mPoolVariablesCount = i4 + 1;
        solverVariableArr[i4] = variable;
        return variable;
    }

    Row getGoal() {
        return this.mGoal;
    }

    ArrayRow getRow(int n) {
        return this.mRows[n];
    }

    float getValueFor(String name) {
        SolverVariable v = getVariable(name, SolverVariable.Type.UNRESTRICTED);
        if (v == null) {
            return 0.0f;
        }
        return v.computedValue;
    }

    public int getObjectVariableValue(Object object) {
        ConstraintAnchor anchor = (ConstraintAnchor) object;
        SolverVariable variable = anchor.getSolverVariable();
        if (variable != null) {
            return (int) (variable.computedValue + 0.5f);
        }
        return 0;
    }

    SolverVariable getVariable(String name, SolverVariable.Type type) {
        if (this.mVariables == null) {
            this.mVariables = new HashMap<>();
        }
        SolverVariable variable = this.mVariables.get(name);
        if (variable == null) {
            return createVariable(name, type);
        }
        return variable;
    }

    public void minimize() throws Exception {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.minimize++;
        }
        if (this.mGoal.isEmpty()) {
            computeValues();
        } else if (this.graphOptimizer || this.newgraphOptimizer) {
            Metrics metrics2 = sMetrics;
            if (metrics2 != null) {
                metrics2.graphOptimizer++;
            }
            boolean fullySolved = true;
            int i = 0;
            while (true) {
                if (i >= this.mNumRows) {
                    break;
                }
                ArrayRow r = this.mRows[i];
                if (r.isSimpleDefinition) {
                    i++;
                } else {
                    fullySolved = false;
                    break;
                }
            }
            if (!fullySolved) {
                minimizeGoal(this.mGoal);
                return;
            }
            Metrics metrics3 = sMetrics;
            if (metrics3 != null) {
                metrics3.fullySolved++;
            }
            computeValues();
        } else {
            minimizeGoal(this.mGoal);
        }
    }

    void minimizeGoal(Row goal) throws Exception {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.minimizeGoal++;
            Metrics metrics2 = sMetrics;
            metrics2.maxVariables = Math.max(metrics2.maxVariables, this.mNumColumns);
            Metrics metrics3 = sMetrics;
            metrics3.maxRows = Math.max(metrics3.maxRows, this.mNumRows);
        }
        enforceBFS(goal);
        optimize(goal, false);
        computeValues();
    }

    final void cleanupRows() {
        int i;
        int i2 = 0;
        while (i2 < this.mNumRows) {
            ArrayRow current = this.mRows[i2];
            if (current.variables.getCurrentSize() == 0) {
                current.isSimpleDefinition = true;
            }
            if (current.isSimpleDefinition) {
                current.variable.computedValue = current.constantValue;
                current.variable.removeFromRow(current);
                int j = i2;
                while (true) {
                    i = this.mNumRows;
                    if (j >= i - 1) {
                        break;
                    }
                    ArrayRow[] arrayRowArr = this.mRows;
                    arrayRowArr[j] = arrayRowArr[j + 1];
                    j++;
                }
                this.mRows[i - 1] = null;
                this.mNumRows = i - 1;
                i2--;
                if (OPTIMIZED_ENGINE) {
                    this.mCache.optimizedArrayRowPool.release(current);
                } else {
                    this.mCache.arrayRowPool.release(current);
                }
            }
            i2++;
        }
    }

    public void addConstraint(ArrayRow row) {
        SolverVariable pivotCandidate;
        if (row == null) {
            return;
        }
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.constraints++;
            if (row.isSimpleDefinition) {
                sMetrics.simpleconstraints++;
            }
        }
        if (this.mNumRows + 1 >= this.mMaxRows || this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        boolean added = false;
        if (!row.isSimpleDefinition) {
            row.updateFromSystem(this);
            if (row.isEmpty()) {
                return;
            }
            row.ensurePositiveConstant();
            if (row.chooseSubject(this)) {
                SolverVariable extra = createExtraVariable();
                row.variable = extra;
                int numRows = this.mNumRows;
                addRow(row);
                if (this.mNumRows == numRows + 1) {
                    added = true;
                    this.mTempGoal.initFromRow(row);
                    optimize(this.mTempGoal, true);
                    if (extra.definitionId == -1) {
                        if (row.variable == extra && (pivotCandidate = row.pickPivot(extra)) != null) {
                            Metrics metrics2 = sMetrics;
                            if (metrics2 != null) {
                                metrics2.pivots++;
                            }
                            row.pivot(pivotCandidate);
                        }
                        if (!row.isSimpleDefinition) {
                            row.variable.updateReferencesWithNewDefinition(this, row);
                        }
                        if (OPTIMIZED_ENGINE) {
                            this.mCache.optimizedArrayRowPool.release(row);
                        } else {
                            this.mCache.arrayRowPool.release(row);
                        }
                        this.mNumRows--;
                    }
                }
            }
            if (!row.hasKeyVariable()) {
                return;
            }
        }
        if (!added) {
            addRow(row);
        }
    }

    private final void addRow(ArrayRow row) {
        int i;
        if (SIMPLIFY_SYNONYMS && row.isSimpleDefinition) {
            row.variable.setFinalValue(this, row.constantValue);
        } else {
            this.mRows[this.mNumRows] = row;
            row.variable.definitionId = this.mNumRows;
            this.mNumRows++;
            row.variable.updateReferencesWithNewDefinition(this, row);
        }
        if (SIMPLIFY_SYNONYMS && this.hasSimpleDefinition) {
            int i2 = 0;
            while (i2 < this.mNumRows) {
                if (this.mRows[i2] == null) {
                    System.out.println("WTF");
                }
                ArrayRow[] arrayRowArr = this.mRows;
                if (arrayRowArr[i2] != null && arrayRowArr[i2].isSimpleDefinition) {
                    ArrayRow removedRow = this.mRows[i2];
                    removedRow.variable.setFinalValue(this, removedRow.constantValue);
                    if (OPTIMIZED_ENGINE) {
                        this.mCache.optimizedArrayRowPool.release(removedRow);
                    } else {
                        this.mCache.arrayRowPool.release(removedRow);
                    }
                    this.mRows[i2] = null;
                    int lastRow = i2 + 1;
                    int j = i2 + 1;
                    while (true) {
                        i = this.mNumRows;
                        if (j >= i) {
                            break;
                        }
                        ArrayRow[] arrayRowArr2 = this.mRows;
                        arrayRowArr2[j - 1] = arrayRowArr2[j];
                        if (arrayRowArr2[j - 1].variable.definitionId == j) {
                            this.mRows[j - 1].variable.definitionId = j - 1;
                        }
                        lastRow = j;
                        j++;
                    }
                    if (lastRow < i) {
                        this.mRows[lastRow] = null;
                    }
                    this.mNumRows = i - 1;
                    i2--;
                }
                i2++;
            }
            this.hasSimpleDefinition = false;
        }
    }

    public void removeRow(ArrayRow row) {
        int i;
        if (row.isSimpleDefinition && row.variable != null) {
            if (row.variable.definitionId != -1) {
                int i2 = row.variable.definitionId;
                while (true) {
                    i = this.mNumRows;
                    if (i2 >= i - 1) {
                        break;
                    }
                    SolverVariable rowVariable = this.mRows[i2 + 1].variable;
                    if (rowVariable.definitionId == i2 + 1) {
                        rowVariable.definitionId = i2;
                    }
                    ArrayRow[] arrayRowArr = this.mRows;
                    arrayRowArr[i2] = arrayRowArr[i2 + 1];
                    i2++;
                }
                this.mNumRows = i - 1;
            }
            if (!row.variable.isFinalValue) {
                row.variable.setFinalValue(this, row.constantValue);
            }
            if (OPTIMIZED_ENGINE) {
                this.mCache.optimizedArrayRowPool.release(row);
            } else {
                this.mCache.arrayRowPool.release(row);
            }
        }
    }

    private final int optimize(Row goal, boolean b) {
        Metrics metrics = sMetrics;
        if (metrics != null) {
            metrics.optimize++;
        }
        boolean done = false;
        int tries = 0;
        for (int i = 0; i < this.mNumColumns; i++) {
            this.mAlreadyTestedCandidates[i] = false;
        }
        while (!done) {
            Metrics metrics2 = sMetrics;
            if (metrics2 != null) {
                metrics2.iterations++;
            }
            tries++;
            if (tries >= this.mNumColumns * 2) {
                return tries;
            }
            if (goal.getKey() != null) {
                this.mAlreadyTestedCandidates[goal.getKey().id] = true;
            }
            SolverVariable pivotCandidate = goal.getPivotCandidate(this, this.mAlreadyTestedCandidates);
            if (pivotCandidate != null) {
                if (this.mAlreadyTestedCandidates[pivotCandidate.id]) {
                    return tries;
                }
                this.mAlreadyTestedCandidates[pivotCandidate.id] = true;
            }
            if (pivotCandidate != null) {
                float min = Float.MAX_VALUE;
                int pivotRowIndex = -1;
                for (int i2 = 0; i2 < this.mNumRows; i2++) {
                    ArrayRow current = this.mRows[i2];
                    SolverVariable variable = current.variable;
                    if (variable.mType != SolverVariable.Type.UNRESTRICTED && !current.isSimpleDefinition && current.hasVariable(pivotCandidate)) {
                        float a_j = current.variables.get(pivotCandidate);
                        if (a_j < 0.0f) {
                            float value = (-current.constantValue) / a_j;
                            if (value < min) {
                                min = value;
                                pivotRowIndex = i2;
                            }
                        }
                    }
                }
                if (pivotRowIndex > -1) {
                    ArrayRow pivotEquation = this.mRows[pivotRowIndex];
                    pivotEquation.variable.definitionId = -1;
                    Metrics metrics3 = sMetrics;
                    if (metrics3 != null) {
                        metrics3.pivots++;
                    }
                    pivotEquation.pivot(pivotCandidate);
                    pivotEquation.variable.definitionId = pivotRowIndex;
                    pivotEquation.variable.updateReferencesWithNewDefinition(this, pivotEquation);
                }
            } else {
                done = true;
            }
        }
        return tries;
    }

    private int enforceBFS(Row goal) throws Exception {
        float f;
        boolean infeasibleSystem;
        boolean infeasibleSystem2;
        int tries = 0;
        boolean infeasibleSystem3 = false;
        int i = 0;
        while (true) {
            f = 0.0f;
            if (i >= this.mNumRows) {
                break;
            }
            SolverVariable variable = this.mRows[i].variable;
            if (variable.mType == SolverVariable.Type.UNRESTRICTED || this.mRows[i].constantValue >= 0.0f) {
                i++;
            } else {
                infeasibleSystem3 = true;
                break;
            }
        }
        if (infeasibleSystem3) {
            boolean done = false;
            tries = 0;
            while (!done) {
                Metrics metrics = sMetrics;
                if (metrics != null) {
                    metrics.bfs++;
                }
                tries++;
                float min = Float.MAX_VALUE;
                int strength = 0;
                int pivotRowIndex = -1;
                int pivotColumnIndex = -1;
                int i2 = 0;
                while (i2 < this.mNumRows) {
                    ArrayRow current = this.mRows[i2];
                    SolverVariable variable2 = current.variable;
                    if (variable2.mType == SolverVariable.Type.UNRESTRICTED) {
                        infeasibleSystem = infeasibleSystem3;
                    } else if (current.isSimpleDefinition) {
                        infeasibleSystem = infeasibleSystem3;
                    } else if (current.constantValue >= f) {
                        infeasibleSystem = infeasibleSystem3;
                    } else if (SKIP_COLUMNS) {
                        int size = current.variables.getCurrentSize();
                        int j = 0;
                        while (j < size) {
                            SolverVariable candidate = current.variables.getVariable(j);
                            float a_j = current.variables.get(candidate);
                            if (a_j <= f) {
                                infeasibleSystem2 = infeasibleSystem3;
                            } else {
                                int k = 0;
                                while (true) {
                                    infeasibleSystem2 = infeasibleSystem3;
                                    if (k < 9) {
                                        float value = candidate.strengthVector[k] / a_j;
                                        if ((value < min && k == strength) || k > strength) {
                                            min = value;
                                            pivotRowIndex = i2;
                                            pivotColumnIndex = candidate.id;
                                            strength = k;
                                        }
                                        k++;
                                        infeasibleSystem3 = infeasibleSystem2;
                                    }
                                }
                            }
                            j++;
                            infeasibleSystem3 = infeasibleSystem2;
                            f = 0.0f;
                        }
                        infeasibleSystem = infeasibleSystem3;
                    } else {
                        infeasibleSystem = infeasibleSystem3;
                        for (int j2 = 1; j2 < this.mNumColumns; j2++) {
                            SolverVariable candidate2 = this.mCache.mIndexedVariables[j2];
                            float a_j2 = current.variables.get(candidate2);
                            if (a_j2 > 0.0f) {
                                for (int k2 = 0; k2 < 9; k2++) {
                                    float value2 = candidate2.strengthVector[k2] / a_j2;
                                    if ((value2 < min && k2 == strength) || k2 > strength) {
                                        min = value2;
                                        pivotRowIndex = i2;
                                        pivotColumnIndex = j2;
                                        strength = k2;
                                    }
                                }
                            }
                        }
                    }
                    i2++;
                    infeasibleSystem3 = infeasibleSystem;
                    f = 0.0f;
                }
                boolean infeasibleSystem4 = infeasibleSystem3;
                if (pivotRowIndex != -1) {
                    ArrayRow pivotEquation = this.mRows[pivotRowIndex];
                    pivotEquation.variable.definitionId = -1;
                    Metrics metrics2 = sMetrics;
                    if (metrics2 != null) {
                        metrics2.pivots++;
                    }
                    pivotEquation.pivot(this.mCache.mIndexedVariables[pivotColumnIndex]);
                    pivotEquation.variable.definitionId = pivotRowIndex;
                    pivotEquation.variable.updateReferencesWithNewDefinition(this, pivotEquation);
                } else {
                    done = true;
                }
                if (tries > this.mNumColumns / 2) {
                    done = true;
                }
                infeasibleSystem3 = infeasibleSystem4;
                f = 0.0f;
            }
        }
        return tries;
    }

    private void computeValues() {
        for (int i = 0; i < this.mNumRows; i++) {
            ArrayRow row = this.mRows[i];
            row.variable.computedValue = row.constantValue;
        }
    }

    private void displayRows() {
        displaySolverVariables();
        String s = "";
        for (int i = 0; i < this.mNumRows; i++) {
            s = (s + this.mRows[i]) + "\n";
        }
        System.out.println(s + this.mGoal + "\n");
    }

    public void displayReadableRows() {
        displaySolverVariables();
        String s = " num vars " + this.mVariablesID + "\n";
        for (int i = 0; i < this.mVariablesID + 1; i++) {
            SolverVariable variable = this.mCache.mIndexedVariables[i];
            if (variable != null && variable.isFinalValue) {
                s = s + " $[" + i + "] => " + variable + " = " + variable.computedValue + "\n";
            }
        }
        String s2 = s + "\n";
        for (int i2 = 0; i2 < this.mVariablesID + 1; i2++) {
            SolverVariable variable2 = this.mCache.mIndexedVariables[i2];
            if (variable2 != null && variable2.isSynonym) {
                SolverVariable synonym = this.mCache.mIndexedVariables[variable2.synonym];
                s2 = s2 + " ~[" + i2 + "] => " + variable2 + " = " + synonym + " + " + variable2.synonymDelta + "\n";
            }
        }
        String s3 = s2 + "\n\n #  ";
        for (int i3 = 0; i3 < this.mNumRows; i3++) {
            s3 = (s3 + this.mRows[i3].toReadableString()) + "\n #  ";
        }
        if (this.mGoal != null) {
            s3 = s3 + "Goal: " + this.mGoal + "\n";
        }
        System.out.println(s3);
    }

    public void displayVariablesReadableRows() {
        displaySolverVariables();
        String s = "";
        for (int i = 0; i < this.mNumRows; i++) {
            if (this.mRows[i].variable.mType == SolverVariable.Type.UNRESTRICTED) {
                s = (s + this.mRows[i].toReadableString()) + "\n";
            }
        }
        System.out.println(s + this.mGoal + "\n");
    }

    public int getMemoryUsed() {
        int actualRowSize = 0;
        for (int i = 0; i < this.mNumRows; i++) {
            ArrayRow[] arrayRowArr = this.mRows;
            if (arrayRowArr[i] != null) {
                actualRowSize += arrayRowArr[i].sizeInBytes();
            }
        }
        return actualRowSize;
    }

    public int getNumEquations() {
        return this.mNumRows;
    }

    public int getNumVariables() {
        return this.mVariablesID;
    }

    void displaySystemInformation() {
        int rowSize = 0;
        for (int i = 0; i < this.TABLE_SIZE; i++) {
            ArrayRow[] arrayRowArr = this.mRows;
            if (arrayRowArr[i] != null) {
                rowSize += arrayRowArr[i].sizeInBytes();
            }
        }
        int actualRowSize = 0;
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            ArrayRow[] arrayRowArr2 = this.mRows;
            if (arrayRowArr2[i2] != null) {
                actualRowSize += arrayRowArr2[i2].sizeInBytes();
            }
        }
        PrintStream printStream = System.out;
        StringBuilder sb = new StringBuilder();
        sb.append("Linear System -> Table size: ");
        sb.append(this.TABLE_SIZE);
        sb.append(" (");
        int i3 = this.TABLE_SIZE;
        sb.append(getDisplaySize(i3 * i3));
        sb.append(") -- row sizes: ");
        sb.append(getDisplaySize(rowSize));
        sb.append(", actual size: ");
        sb.append(getDisplaySize(actualRowSize));
        sb.append(" rows: ");
        sb.append(this.mNumRows);
        sb.append("/");
        sb.append(this.mMaxRows);
        sb.append(" cols: ");
        sb.append(this.mNumColumns);
        sb.append("/");
        sb.append(this.mMaxColumns);
        sb.append(" ");
        sb.append(0);
        sb.append(" occupied cells, ");
        sb.append(getDisplaySize(0));
        printStream.println(sb.toString());
    }

    private void displaySolverVariables() {
        String s = "Display Rows (" + this.mNumRows + "x" + this.mNumColumns + ")\n";
        System.out.println(s);
    }

    private String getDisplaySize(int n) {
        int mb = ((n * 4) / 1024) / 1024;
        if (mb > 0) {
            return "" + mb + " Mb";
        }
        int kb = (n * 4) / 1024;
        if (kb > 0) {
            return "" + kb + " Kb";
        }
        return "" + (n * 4) + " bytes";
    }

    public Cache getCache() {
        return this.mCache;
    }

    private String getDisplayStrength(int strength) {
        if (strength == 1) {
            return "LOW";
        }
        if (strength == 2) {
            return "MEDIUM";
        }
        if (strength == 3) {
            return "HIGH";
        }
        if (strength == 4) {
            return "HIGHEST";
        }
        if (strength == 5) {
            return "EQUALITY";
        }
        if (strength == 8) {
            return "FIXED";
        }
        if (strength == 6) {
            return "BARRIER";
        }
        return "NONE";
    }

    public void addGreaterThan(SolverVariable a, SolverVariable b, int margin, int strength) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowGreaterThan(a, b, slack, margin);
        if (strength != 8) {
            float slackValue = row.variables.get(slack);
            addSingleError(row, (int) ((-1.0f) * slackValue), strength);
        }
        addConstraint(row);
    }

    public void addGreaterBarrier(SolverVariable a, SolverVariable b, int margin, boolean hasMatchConstraintWidgets) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowGreaterThan(a, b, slack, margin);
        addConstraint(row);
    }

    public void addLowerThan(SolverVariable a, SolverVariable b, int margin, int strength) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowLowerThan(a, b, slack, margin);
        if (strength != 8) {
            float slackValue = row.variables.get(slack);
            addSingleError(row, (int) ((-1.0f) * slackValue), strength);
        }
        addConstraint(row);
    }

    public void addLowerBarrier(SolverVariable a, SolverVariable b, int margin, boolean hasMatchConstraintWidgets) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowLowerThan(a, b, slack, margin);
        addConstraint(row);
    }

    public void addCentering(SolverVariable a, SolverVariable b, int m1, float bias, SolverVariable c, SolverVariable d, int m2, int strength) {
        ArrayRow row = createRow();
        row.createRowCentering(a, b, m1, bias, c, d, m2);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
    }

    public void addRatio(SolverVariable a, SolverVariable b, SolverVariable c, SolverVariable d, float ratio, int strength) {
        ArrayRow row = createRow();
        row.createRowDimensionRatio(a, b, c, d, ratio);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
    }

    public void addSynonym(SolverVariable a, SolverVariable b, int margin) {
        if (a.definitionId == -1 && margin == 0) {
            if (b.isSynonym) {
                margin = (int) (margin + b.synonymDelta);
                b = this.mCache.mIndexedVariables[b.synonym];
            }
            if (a.isSynonym) {
                int margin2 = (int) (margin - a.synonymDelta);
                SolverVariable a2 = this.mCache.mIndexedVariables[a.synonym];
                return;
            }
            a.setSynonym(this, b, 0.0f);
            return;
        }
        addEquality(a, b, margin, 8);
    }

    public ArrayRow addEquality(SolverVariable a, SolverVariable b, int margin, int strength) {
        if (USE_BASIC_SYNONYMS && strength == 8 && b.isFinalValue && a.definitionId == -1) {
            a.setFinalValue(this, b.computedValue + margin);
            return null;
        }
        ArrayRow row = createRow();
        row.createRowEquals(a, b, margin);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
        return row;
    }

    public void addEquality(SolverVariable a, int value) {
        if (USE_BASIC_SYNONYMS && a.definitionId == -1) {
            a.setFinalValue(this, value);
            for (int i = 0; i < this.mVariablesID + 1; i++) {
                SolverVariable variable = this.mCache.mIndexedVariables[i];
                if (variable != null && variable.isSynonym && variable.synonym == a.id) {
                    variable.setFinalValue(this, value + variable.synonymDelta);
                }
            }
            return;
        }
        int idx = a.definitionId;
        if (a.definitionId != -1) {
            ArrayRow row = this.mRows[idx];
            if (row.isSimpleDefinition) {
                row.constantValue = value;
                return;
            } else if (row.variables.getCurrentSize() == 0) {
                row.isSimpleDefinition = true;
                row.constantValue = value;
                return;
            } else {
                ArrayRow newRow = createRow();
                newRow.createRowEquals(a, value);
                addConstraint(newRow);
                return;
            }
        }
        ArrayRow row2 = createRow();
        row2.createRowDefinition(a, value);
        addConstraint(row2);
    }

    public static ArrayRow createRowDimensionPercent(LinearSystem linearSystem, SolverVariable variableA, SolverVariable variableC, float percent) {
        ArrayRow row = linearSystem.createRow();
        return row.createRowDimensionPercent(variableA, variableC, percent);
    }

    public void addCenterPoint(ConstraintWidget widget, ConstraintWidget target, float angle, int radius) {
        SolverVariable Al = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.LEFT));
        SolverVariable At = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.TOP));
        SolverVariable Ar = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.RIGHT));
        SolverVariable Ab = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.BOTTOM));
        SolverVariable Bl = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.LEFT));
        SolverVariable Bt = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.TOP));
        SolverVariable Br = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.RIGHT));
        SolverVariable Bb = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.BOTTOM));
        ArrayRow row = createRow();
        float angleComponent = (float) (Math.sin(angle) * radius);
        row.createRowWithAngle(At, Ab, Bt, Bb, angleComponent);
        addConstraint(row);
        ArrayRow row2 = createRow();
        float angleComponent2 = (float) (Math.cos(angle) * radius);
        row2.createRowWithAngle(Al, Ar, Bl, Br, angleComponent2);
        addConstraint(row2);
    }
}
