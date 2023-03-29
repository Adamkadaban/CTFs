package androidx.appcompat.app;

import android.util.AttributeSet;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Deque;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
class LayoutIncludeDetector {
    private final Deque<WeakReference<XmlPullParser>> mXmlParserStack = new ArrayDeque();

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean detect(AttributeSet attrs) {
        if (attrs instanceof XmlPullParser) {
            XmlPullParser xmlAttrs = (XmlPullParser) attrs;
            if (xmlAttrs.getDepth() == 1) {
                XmlPullParser ancestorXmlAttrs = popOutdatedAttrHolders(this.mXmlParserStack);
                this.mXmlParserStack.push(new WeakReference<>(xmlAttrs));
                return shouldInheritContext(xmlAttrs, ancestorXmlAttrs);
            }
            return false;
        }
        return false;
    }

    private static boolean shouldInheritContext(XmlPullParser parser, XmlPullParser previousParser) {
        if (previousParser != null && parser != previousParser) {
            try {
                if (previousParser.getEventType() == 2) {
                    return "include".equals(previousParser.getName());
                }
                return false;
            } catch (XmlPullParserException e) {
                return false;
            }
        }
        return false;
    }

    private static XmlPullParser popOutdatedAttrHolders(Deque<WeakReference<XmlPullParser>> xmlParserStack) {
        while (!xmlParserStack.isEmpty()) {
            XmlPullParser parser = xmlParserStack.peek().get();
            if (isParserOutdated(parser)) {
                xmlParserStack.pop();
            } else {
                return parser;
            }
        }
        return null;
    }

    private static boolean isParserOutdated(XmlPullParser parser) {
        if (parser != null) {
            try {
                if (parser.getEventType() != 3) {
                    return parser.getEventType() == 1;
                }
                return true;
            } catch (XmlPullParserException e) {
                return true;
            }
        }
        return true;
    }
}
