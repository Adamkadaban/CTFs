package androidx.constraintlayout.core.parser;

import java.util.Iterator;
/* loaded from: classes.dex */
public class CLObject extends CLContainer implements Iterable<CLKey> {
    public CLObject(char[] content) {
        super(content);
    }

    public static CLObject allocate(char[] content) {
        return new CLObject(content);
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toJSON() {
        StringBuilder json = new StringBuilder(getDebugName() + "{ ");
        boolean first = true;
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            if (!first) {
                json.append(", ");
            } else {
                first = false;
            }
            json.append(element.toJSON());
        }
        json.append(" }");
        return json.toString();
    }

    public String toFormattedJSON() {
        return toFormattedJSON(0, 0);
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toFormattedJSON(int indent, int forceIndent) {
        StringBuilder json = new StringBuilder(getDebugName());
        json.append("{\n");
        boolean first = true;
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            if (!first) {
                json.append(",\n");
            } else {
                first = false;
            }
            json.append(element.toFormattedJSON(BASE_INDENT + indent, forceIndent - 1));
        }
        json.append("\n");
        addIndent(json, indent);
        json.append("}");
        return json.toString();
    }

    @Override // java.lang.Iterable
    public Iterator<CLKey> iterator() {
        return new CLObjectIterator(this);
    }

    /* loaded from: classes.dex */
    private class CLObjectIterator implements Iterator {
        int index = 0;
        CLObject myObject;

        public CLObjectIterator(CLObject clObject) {
            this.myObject = clObject;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.index < this.myObject.size();
        }

        @Override // java.util.Iterator
        public Object next() {
            CLKey key = (CLKey) this.myObject.mElements.get(this.index);
            this.index++;
            return key;
        }
    }
}
