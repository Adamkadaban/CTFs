package androidx.constraintlayout.core.parser;

import java.io.PrintStream;
/* loaded from: classes.dex */
public class CLElement {
    private int line;
    protected CLContainer mContainer;
    private final char[] mContent;
    protected static int MAX_LINE = 80;
    protected static int BASE_INDENT = 2;
    protected long start = -1;
    protected long end = Long.MAX_VALUE;

    public CLElement(char[] content) {
        this.mContent = content;
    }

    public boolean notStarted() {
        return this.start == -1;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public int getLine() {
        return this.line;
    }

    public void setStart(long start) {
        this.start = start;
    }

    public long getStart() {
        return this.start;
    }

    public long getEnd() {
        return this.end;
    }

    public void setEnd(long end) {
        if (this.end != Long.MAX_VALUE) {
            return;
        }
        this.end = end;
        if (CLParser.DEBUG) {
            PrintStream printStream = System.out;
            printStream.println("closing " + hashCode() + " -> " + this);
        }
        CLContainer cLContainer = this.mContainer;
        if (cLContainer != null) {
            cLContainer.add(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void addIndent(StringBuilder builder, int indent) {
        for (int i = 0; i < indent; i++) {
            builder.append(' ');
        }
    }

    public String toString() {
        long j = this.start;
        long j2 = this.end;
        if (j > j2 || j2 == Long.MAX_VALUE) {
            return getClass() + " (INVALID, " + this.start + "-" + this.end + ")";
        }
        String content = new String(this.mContent);
        String content2 = content.substring((int) this.start, ((int) this.end) + 1);
        return getStrClass() + " (" + this.start + " : " + this.end + ") <<" + content2 + ">>";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String getStrClass() {
        String myClass = getClass().toString();
        return myClass.substring(myClass.lastIndexOf(46) + 1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String getDebugName() {
        if (CLParser.DEBUG) {
            return getStrClass() + " -> ";
        }
        return "";
    }

    public String content() {
        String content = new String(this.mContent);
        long j = this.end;
        if (j != Long.MAX_VALUE) {
            long j2 = this.start;
            if (j >= j2) {
                return content.substring((int) j2, ((int) j) + 1);
            }
        }
        long j3 = this.start;
        return content.substring((int) j3, ((int) j3) + 1);
    }

    public boolean isDone() {
        return this.end != Long.MAX_VALUE;
    }

    public void setContainer(CLContainer element) {
        this.mContainer = element;
    }

    public CLElement getContainer() {
        return this.mContainer;
    }

    public boolean isStarted() {
        return this.start > -1;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String toJSON() {
        return "";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String toFormattedJSON(int indent, int forceIndent) {
        return "";
    }

    public int getInt() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getInt();
        }
        return 0;
    }

    public float getFloat() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getFloat();
        }
        return Float.NaN;
    }
}
