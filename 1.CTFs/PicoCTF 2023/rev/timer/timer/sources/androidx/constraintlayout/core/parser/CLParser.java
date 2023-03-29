package androidx.constraintlayout.core.parser;

import java.io.PrintStream;
/* loaded from: classes.dex */
public class CLParser {
    static boolean DEBUG = false;
    private boolean hasComment = false;
    private int lineNumber;
    private String mContent;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public enum TYPE {
        UNKNOWN,
        OBJECT,
        ARRAY,
        NUMBER,
        STRING,
        KEY,
        TOKEN
    }

    public static CLObject parse(String string) throws CLParsingException {
        return new CLParser(string).parse();
    }

    public CLParser(String content) {
        this.mContent = content;
    }

    /* JADX WARN: Code restructure failed: missing block: B:82:0x0145, code lost:
        if (r6 != ':') goto L31;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.constraintlayout.core.parser.CLObject parse() throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 476
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.parser.CLParser.parse():androidx.constraintlayout.core.parser.CLObject");
    }

    private CLElement getNextJsonElement(int position, char c, CLElement currentElement, char[] content) throws CLParsingException {
        switch (c) {
            case '\t':
            case '\n':
            case '\r':
            case ' ':
            case ',':
            case ':':
                return currentElement;
            case '\"':
            case '\'':
                if (currentElement instanceof CLObject) {
                    return createElement(currentElement, position, TYPE.KEY, true, content);
                }
                return createElement(currentElement, position, TYPE.STRING, true, content);
            case '+':
            case '-':
            case '.':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return createElement(currentElement, position, TYPE.NUMBER, true, content);
            case '/':
                if (position + 1 < content.length && content[position + 1] == '/') {
                    this.hasComment = true;
                    return currentElement;
                }
                return currentElement;
            case '[':
                return createElement(currentElement, position, TYPE.ARRAY, true, content);
            case ']':
            case '}':
                currentElement.setEnd(position - 1);
                CLElement currentElement2 = currentElement.getContainer();
                currentElement2.setEnd(position);
                return currentElement2;
            case '{':
                return createElement(currentElement, position, TYPE.OBJECT, true, content);
            default:
                if ((currentElement instanceof CLContainer) && !(currentElement instanceof CLObject)) {
                    CLElement currentElement3 = createElement(currentElement, position, TYPE.TOKEN, true, content);
                    CLToken token = (CLToken) currentElement3;
                    if (!token.validate(c, position)) {
                        throw new CLParsingException("incorrect token <" + c + "> at line " + this.lineNumber, token);
                    }
                    return currentElement3;
                }
                return createElement(currentElement, position, TYPE.KEY, true, content);
        }
    }

    private CLElement createElement(CLElement currentElement, int position, TYPE type, boolean applyStart, char[] content) {
        CLElement newElement = null;
        if (DEBUG) {
            PrintStream printStream = System.out;
            printStream.println("CREATE " + type + " at " + content[position]);
        }
        switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[type.ordinal()]) {
            case 1:
                newElement = CLObject.allocate(content);
                position++;
                break;
            case 2:
                newElement = CLArray.allocate(content);
                position++;
                break;
            case 3:
                newElement = CLString.allocate(content);
                break;
            case 4:
                newElement = CLNumber.allocate(content);
                break;
            case 5:
                newElement = CLKey.allocate(content);
                break;
            case 6:
                newElement = CLToken.allocate(content);
                break;
        }
        if (newElement == null) {
            return null;
        }
        newElement.setLine(this.lineNumber);
        if (applyStart) {
            newElement.setStart(position);
        }
        if (currentElement instanceof CLContainer) {
            CLContainer container = (CLContainer) currentElement;
            newElement.setContainer(container);
        }
        return newElement;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: androidx.constraintlayout.core.parser.CLParser$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE;

        static {
            int[] iArr = new int[TYPE.values().length];
            $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE = iArr;
            try {
                iArr[TYPE.OBJECT.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[TYPE.ARRAY.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[TYPE.STRING.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[TYPE.NUMBER.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[TYPE.KEY.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$parser$CLParser$TYPE[TYPE.TOKEN.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
        }
    }
}
