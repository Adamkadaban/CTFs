package androidx.transition;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.util.AttributeSet;
import android.util.Xml;
import android.view.InflateException;
import android.view.ViewGroup;
import androidx.collection.ArrayMap;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.content.res.TypedArrayUtils;
import java.io.IOException;
import java.lang.reflect.Constructor;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class TransitionInflater {
    private final Context mContext;
    private static final Class<?>[] CONSTRUCTOR_SIGNATURE = {Context.class, AttributeSet.class};
    private static final ArrayMap<String, Constructor<?>> CONSTRUCTORS = new ArrayMap<>();

    private TransitionInflater(Context context) {
        this.mContext = context;
    }

    public static TransitionInflater from(Context context) {
        return new TransitionInflater(context);
    }

    public Transition inflateTransition(int resource) {
        XmlResourceParser parser = this.mContext.getResources().getXml(resource);
        try {
            try {
                return createTransitionFromXml(parser, Xml.asAttributeSet(parser), null);
            } catch (IOException e) {
                throw new InflateException(parser.getPositionDescription() + ": " + e.getMessage(), e);
            } catch (XmlPullParserException e2) {
                throw new InflateException(e2.getMessage(), e2);
            }
        } finally {
            parser.close();
        }
    }

    public TransitionManager inflateTransitionManager(int resource, ViewGroup sceneRoot) {
        XmlResourceParser parser = this.mContext.getResources().getXml(resource);
        try {
            try {
                return createTransitionManagerFromXml(parser, Xml.asAttributeSet(parser), sceneRoot);
            } catch (IOException e) {
                InflateException ex = new InflateException(parser.getPositionDescription() + ": " + e.getMessage());
                ex.initCause(e);
                throw ex;
            } catch (XmlPullParserException e2) {
                InflateException ex2 = new InflateException(e2.getMessage());
                ex2.initCause(e2);
                throw ex2;
            }
        } finally {
            parser.close();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:82:0x018a, code lost:
        return r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private androidx.transition.Transition createTransitionFromXml(org.xmlpull.v1.XmlPullParser r9, android.util.AttributeSet r10, androidx.transition.Transition r11) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            Method dump skipped, instructions count: 395
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.TransitionInflater.createTransitionFromXml(org.xmlpull.v1.XmlPullParser, android.util.AttributeSet, androidx.transition.Transition):androidx.transition.Transition");
    }

    private Object createCustom(AttributeSet attrs, Class<?> expectedType, String tag) {
        Object newInstance;
        Class<?> c;
        String className = attrs.getAttributeValue(null, "class");
        if (className == null) {
            throw new InflateException(tag + " tag must have a 'class' attribute");
        }
        try {
            ArrayMap<String, Constructor<?>> arrayMap = CONSTRUCTORS;
            synchronized (arrayMap) {
                Constructor<?> constructor = arrayMap.get(className);
                if (constructor == null && (c = Class.forName(className, false, this.mContext.getClassLoader()).asSubclass(expectedType)) != null) {
                    constructor = c.getConstructor(CONSTRUCTOR_SIGNATURE);
                    constructor.setAccessible(true);
                    arrayMap.put(className, constructor);
                }
                newInstance = constructor.newInstance(this.mContext, attrs);
            }
            return newInstance;
        } catch (Exception e) {
            throw new InflateException("Could not instantiate " + expectedType + " class " + className, e);
        }
    }

    private void getTargetIds(XmlPullParser parser, AttributeSet attrs, Transition transition) throws XmlPullParserException, IOException {
        int depth = parser.getDepth();
        while (true) {
            int type = parser.next();
            if ((type != 3 || parser.getDepth() > depth) && type != 1) {
                if (type == 2) {
                    String name = parser.getName();
                    if (name.equals(TypedValues.AttributesType.S_TARGET)) {
                        TypedArray a = this.mContext.obtainStyledAttributes(attrs, Styleable.TRANSITION_TARGET);
                        int id = TypedArrayUtils.getNamedResourceId(a, parser, "targetId", 1, 0);
                        if (id == 0) {
                            int id2 = TypedArrayUtils.getNamedResourceId(a, parser, "excludeId", 2, 0);
                            if (id2 != 0) {
                                transition.excludeTarget(id2, true);
                            } else {
                                String transitionName = TypedArrayUtils.getNamedString(a, parser, "targetName", 4);
                                if (transitionName != null) {
                                    transition.addTarget(transitionName);
                                } else {
                                    String transitionName2 = TypedArrayUtils.getNamedString(a, parser, "excludeName", 5);
                                    if (transitionName2 != null) {
                                        transition.excludeTarget(transitionName2, true);
                                    } else {
                                        String className = TypedArrayUtils.getNamedString(a, parser, "excludeClass", 3);
                                        if (className != null) {
                                            try {
                                                Class<?> clazz = Class.forName(className);
                                                transition.excludeTarget(clazz, true);
                                            } catch (ClassNotFoundException e) {
                                                a.recycle();
                                                throw new RuntimeException("Could not create " + className, e);
                                            }
                                        } else {
                                            String className2 = TypedArrayUtils.getNamedString(a, parser, "targetClass", 0);
                                            if (className2 != null) {
                                                Class<?> clazz2 = Class.forName(className2);
                                                transition.addTarget(clazz2);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            transition.addTarget(id);
                        }
                        a.recycle();
                    } else {
                        throw new RuntimeException("Unknown scene name: " + parser.getName());
                    }
                }
            } else {
                return;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0056, code lost:
        return r1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private androidx.transition.TransitionManager createTransitionManagerFromXml(org.xmlpull.v1.XmlPullParser r8, android.util.AttributeSet r9, android.view.ViewGroup r10) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            r7 = this;
            int r0 = r8.getDepth()
            r1 = 0
        L5:
            int r2 = r8.next()
            r3 = r2
            r4 = 3
            if (r2 != r4) goto L13
            int r2 = r8.getDepth()
            if (r2 <= r0) goto L56
        L13:
            r2 = 1
            if (r3 == r2) goto L56
            r2 = 2
            if (r3 == r2) goto L1a
            goto L5
        L1a:
            java.lang.String r2 = r8.getName()
            java.lang.String r4 = "transitionManager"
            boolean r4 = r2.equals(r4)
            if (r4 == 0) goto L2d
            androidx.transition.TransitionManager r4 = new androidx.transition.TransitionManager
            r4.<init>()
            r1 = r4
            goto L3a
        L2d:
            java.lang.String r4 = "transition"
            boolean r4 = r2.equals(r4)
            if (r4 == 0) goto L3b
            if (r1 == 0) goto L3b
            r7.loadTransition(r9, r8, r10, r1)
        L3a:
            goto L5
        L3b:
            java.lang.RuntimeException r4 = new java.lang.RuntimeException
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            java.lang.String r6 = "Unknown scene name: "
            r5.append(r6)
            java.lang.String r6 = r8.getName()
            r5.append(r6)
            java.lang.String r5 = r5.toString()
            r4.<init>(r5)
            throw r4
        L56:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.TransitionInflater.createTransitionManagerFromXml(org.xmlpull.v1.XmlPullParser, android.util.AttributeSet, android.view.ViewGroup):androidx.transition.TransitionManager");
    }

    private void loadTransition(AttributeSet attrs, XmlPullParser parser, ViewGroup sceneRoot, TransitionManager transitionManager) throws Resources.NotFoundException {
        Transition transition;
        TypedArray a = this.mContext.obtainStyledAttributes(attrs, Styleable.TRANSITION_MANAGER);
        int transitionId = TypedArrayUtils.getNamedResourceId(a, parser, "transition", 2, -1);
        int fromId = TypedArrayUtils.getNamedResourceId(a, parser, "fromScene", 0, -1);
        Scene fromScene = fromId < 0 ? null : Scene.getSceneForLayout(sceneRoot, fromId, this.mContext);
        int toId = TypedArrayUtils.getNamedResourceId(a, parser, "toScene", 1, -1);
        Scene toScene = toId >= 0 ? Scene.getSceneForLayout(sceneRoot, toId, this.mContext) : null;
        if (transitionId >= 0 && (transition = inflateTransition(transitionId)) != null) {
            if (toScene == null) {
                throw new RuntimeException("No toScene for transition ID " + transitionId);
            } else if (fromScene == null) {
                transitionManager.setTransition(toScene, transition);
            } else {
                transitionManager.setTransition(fromScene, toScene, transition);
            }
        }
        a.recycle();
    }
}
