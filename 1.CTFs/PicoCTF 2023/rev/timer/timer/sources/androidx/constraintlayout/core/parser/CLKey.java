package androidx.constraintlayout.core.parser;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class CLKey extends CLContainer {
    private static ArrayList<String> sections;

    static {
        ArrayList<String> arrayList = new ArrayList<>();
        sections = arrayList;
        arrayList.add("ConstraintSets");
        sections.add("Variables");
        sections.add("Generate");
        sections.add(TypedValues.TransitionType.NAME);
        sections.add("KeyFrames");
        sections.add(TypedValues.AttributesType.NAME);
        sections.add("KeyPositions");
        sections.add("KeyCycles");
    }

    public CLKey(char[] content) {
        super(content);
    }

    public static CLElement allocate(char[] content) {
        return new CLKey(content);
    }

    public static CLElement allocate(String name, CLElement value) {
        CLKey key = new CLKey(name.toCharArray());
        key.setStart(0L);
        key.setEnd(name.length() - 1);
        key.set(value);
        return key;
    }

    public String getName() {
        return content();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toJSON() {
        if (this.mElements.size() > 0) {
            return getDebugName() + content() + ": " + this.mElements.get(0).toJSON();
        }
        return getDebugName() + content() + ": <> ";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toFormattedJSON(int indent, int forceIndent) {
        StringBuilder json = new StringBuilder(getDebugName());
        addIndent(json, indent);
        String content = content();
        if (this.mElements.size() > 0) {
            json.append(content);
            json.append(": ");
            if (sections.contains(content)) {
                forceIndent = 3;
            }
            if (forceIndent > 0) {
                json.append(this.mElements.get(0).toFormattedJSON(indent, forceIndent - 1));
            } else {
                String val = this.mElements.get(0).toJSON();
                if (val.length() + indent >= MAX_LINE) {
                    json.append(this.mElements.get(0).toFormattedJSON(indent, forceIndent - 1));
                } else {
                    json.append(val);
                }
            }
            return json.toString();
        }
        return content + ": <> ";
    }

    public void set(CLElement value) {
        if (this.mElements.size() > 0) {
            this.mElements.set(0, value);
        } else {
            this.mElements.add(value);
        }
    }

    public CLElement getValue() {
        if (this.mElements.size() > 0) {
            return this.mElements.get(0);
        }
        return null;
    }
}
