package androidx.constraintlayout.core.parser;
/* loaded from: classes.dex */
public class CLNumber extends CLElement {
    float value;

    public CLNumber(char[] content) {
        super(content);
        this.value = Float.NaN;
    }

    public CLNumber(float value) {
        super(null);
        this.value = Float.NaN;
        this.value = value;
    }

    public static CLElement allocate(char[] content) {
        return new CLNumber(content);
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    protected String toJSON() {
        float value = getFloat();
        int intValue = (int) value;
        if (intValue == value) {
            return "" + intValue;
        }
        return "" + value;
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    protected String toFormattedJSON(int indent, int forceIndent) {
        StringBuilder json = new StringBuilder();
        addIndent(json, indent);
        float value = getFloat();
        int intValue = (int) value;
        if (intValue == value) {
            json.append(intValue);
        } else {
            json.append(value);
        }
        return json.toString();
    }

    public boolean isInt() {
        float value = getFloat();
        int intValue = (int) value;
        return ((float) intValue) == value;
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    public int getInt() {
        if (Float.isNaN(this.value)) {
            this.value = Integer.parseInt(content());
        }
        return (int) this.value;
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    public float getFloat() {
        if (Float.isNaN(this.value)) {
            this.value = Float.parseFloat(content());
        }
        return this.value;
    }

    public void putValue(float value) {
        this.value = value;
    }
}
