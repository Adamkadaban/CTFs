package androidx.constraintlayout.core.parser;
/* loaded from: classes.dex */
public class CLString extends CLElement {
    public CLString(char[] content) {
        super(content);
    }

    public static CLElement allocate(char[] content) {
        return new CLString(content);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toJSON() {
        return "'" + content() + "'";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toFormattedJSON(int indent, int forceIndent) {
        StringBuilder json = new StringBuilder();
        addIndent(json, indent);
        json.append("'");
        json.append(content());
        json.append("'");
        return json.toString();
    }
}
