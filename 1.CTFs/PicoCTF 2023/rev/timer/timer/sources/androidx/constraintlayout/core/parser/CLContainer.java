package androidx.constraintlayout.core.parser;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
/* loaded from: classes.dex */
public class CLContainer extends CLElement {
    ArrayList<CLElement> mElements;

    public CLContainer(char[] content) {
        super(content);
        this.mElements = new ArrayList<>();
    }

    public static CLElement allocate(char[] content) {
        return new CLContainer(content);
    }

    public void add(CLElement element) {
        this.mElements.add(element);
        if (CLParser.DEBUG) {
            PrintStream printStream = System.out;
            printStream.println("added element " + element + " to " + this);
        }
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    public String toString() {
        StringBuilder list = new StringBuilder();
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            if (list.length() > 0) {
                list.append("; ");
            }
            list.append(element);
        }
        return super.toString() + " = <" + ((Object) list) + " >";
    }

    public int size() {
        return this.mElements.size();
    }

    public ArrayList<String> names() {
        ArrayList<String> names = new ArrayList<>();
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            if (element instanceof CLKey) {
                CLKey key = (CLKey) element;
                names.add(key.content());
            }
        }
        return names;
    }

    public boolean has(String name) {
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            if (element instanceof CLKey) {
                CLKey key = (CLKey) element;
                if (key.content().equals(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void put(String name, CLElement value) {
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            CLKey key = (CLKey) element;
            if (key.content().equals(name)) {
                key.set(value);
                return;
            }
        }
        this.mElements.add((CLKey) CLKey.allocate(name, value));
    }

    public void putNumber(String name, float value) {
        put(name, new CLNumber(value));
    }

    public void remove(String name) {
        ArrayList<CLElement> toRemove = new ArrayList<>();
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            CLKey key = (CLKey) element;
            if (key.content().equals(name)) {
                toRemove.add(element);
            }
        }
        Iterator<CLElement> it2 = toRemove.iterator();
        while (it2.hasNext()) {
            this.mElements.remove(it2.next());
        }
    }

    public CLElement get(String name) throws CLParsingException {
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            CLKey key = (CLKey) element;
            if (key.content().equals(name)) {
                return key.getValue();
            }
        }
        throw new CLParsingException("no element for key <" + name + ">", this);
    }

    public int getInt(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element != null) {
            return element.getInt();
        }
        throw new CLParsingException("no int found for key <" + name + ">, found [" + element.getStrClass() + "] : " + element, this);
    }

    public float getFloat(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element != null) {
            return element.getFloat();
        }
        throw new CLParsingException("no float found for key <" + name + ">, found [" + element.getStrClass() + "] : " + element, this);
    }

    public CLArray getArray(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element instanceof CLArray) {
            return (CLArray) element;
        }
        throw new CLParsingException("no array found for key <" + name + ">, found [" + element.getStrClass() + "] : " + element, this);
    }

    public CLObject getObject(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element instanceof CLObject) {
            return (CLObject) element;
        }
        throw new CLParsingException("no object found for key <" + name + ">, found [" + element.getStrClass() + "] : " + element, this);
    }

    public String getString(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element instanceof CLString) {
            return element.content();
        }
        String strClass = null;
        if (element != null) {
            strClass = element.getStrClass();
        }
        throw new CLParsingException("no string found for key <" + name + ">, found [" + strClass + "] : " + element, this);
    }

    public boolean getBoolean(String name) throws CLParsingException {
        CLElement element = get(name);
        if (element instanceof CLToken) {
            return ((CLToken) element).getBoolean();
        }
        throw new CLParsingException("no boolean found for key <" + name + ">, found [" + element.getStrClass() + "] : " + element, this);
    }

    public CLElement getOrNull(String name) {
        Iterator<CLElement> it = this.mElements.iterator();
        while (it.hasNext()) {
            CLElement element = it.next();
            CLKey key = (CLKey) element;
            if (key.content().equals(name)) {
                return key.getValue();
            }
        }
        return null;
    }

    public CLObject getObjectOrNull(String name) {
        CLElement element = getOrNull(name);
        if (element instanceof CLObject) {
            return (CLObject) element;
        }
        return null;
    }

    public CLArray getArrayOrNull(String name) {
        CLElement element = getOrNull(name);
        if (element instanceof CLArray) {
            return (CLArray) element;
        }
        return null;
    }

    public String getStringOrNull(String name) {
        CLElement element = getOrNull(name);
        if (element instanceof CLString) {
            return element.content();
        }
        return null;
    }

    public float getFloatOrNaN(String name) {
        CLElement element = getOrNull(name);
        if (element instanceof CLNumber) {
            return element.getFloat();
        }
        return Float.NaN;
    }

    public CLElement get(int index) throws CLParsingException {
        if (index >= 0 && index < this.mElements.size()) {
            return this.mElements.get(index);
        }
        throw new CLParsingException("no element at index " + index, this);
    }

    public int getInt(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element != null) {
            return element.getInt();
        }
        throw new CLParsingException("no int at index " + index, this);
    }

    public float getFloat(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element != null) {
            return element.getFloat();
        }
        throw new CLParsingException("no float at index " + index, this);
    }

    public CLArray getArray(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element instanceof CLArray) {
            return (CLArray) element;
        }
        throw new CLParsingException("no array at index " + index, this);
    }

    public CLObject getObject(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element instanceof CLObject) {
            return (CLObject) element;
        }
        throw new CLParsingException("no object at index " + index, this);
    }

    public String getString(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element instanceof CLString) {
            return element.content();
        }
        throw new CLParsingException("no string at index " + index, this);
    }

    public boolean getBoolean(int index) throws CLParsingException {
        CLElement element = get(index);
        if (element instanceof CLToken) {
            return ((CLToken) element).getBoolean();
        }
        throw new CLParsingException("no boolean at index " + index, this);
    }

    public CLElement getOrNull(int index) {
        if (index >= 0 && index < this.mElements.size()) {
            return this.mElements.get(index);
        }
        return null;
    }

    public String getStringOrNull(int index) {
        CLElement element = getOrNull(index);
        if (element instanceof CLString) {
            return element.content();
        }
        return null;
    }
}
