package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.util.Log;
import android.util.Xml;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.widget.ConstraintAttribute;
import androidx.constraintlayout.widget.ConstraintLayout;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class KeyFrames {
    private static final String CUSTOM_ATTRIBUTE = "CustomAttribute";
    private static final String CUSTOM_METHOD = "CustomMethod";
    private static final String TAG = "KeyFrames";
    public static final int UNSET = -1;
    static HashMap<String, Constructor<? extends Key>> sKeyMakers;
    private HashMap<Integer, ArrayList<Key>> mFramesMap = new HashMap<>();

    static {
        HashMap<String, Constructor<? extends Key>> hashMap = new HashMap<>();
        sKeyMakers = hashMap;
        try {
            hashMap.put("KeyAttribute", KeyAttributes.class.getConstructor(new Class[0]));
            sKeyMakers.put(TypedValues.PositionType.NAME, KeyPosition.class.getConstructor(new Class[0]));
            sKeyMakers.put(TypedValues.CycleType.NAME, KeyCycle.class.getConstructor(new Class[0]));
            sKeyMakers.put("KeyTimeCycle", KeyTimeCycle.class.getConstructor(new Class[0]));
            sKeyMakers.put(TypedValues.TriggerType.NAME, KeyTrigger.class.getConstructor(new Class[0]));
        } catch (NoSuchMethodException e) {
            Log.e(TAG, "unable to load", e);
        }
    }

    public void addKey(Key key) {
        if (!this.mFramesMap.containsKey(Integer.valueOf(key.mTargetId))) {
            this.mFramesMap.put(Integer.valueOf(key.mTargetId), new ArrayList<>());
        }
        ArrayList<Key> frames = this.mFramesMap.get(Integer.valueOf(key.mTargetId));
        if (frames != null) {
            frames.add(key);
        }
    }

    public KeyFrames() {
    }

    public KeyFrames(Context context, XmlPullParser parser) {
        Key key = null;
        try {
            int eventType = parser.getEventType();
            while (eventType != 1) {
                switch (eventType) {
                    case 2:
                        String tagName = parser.getName();
                        if (sKeyMakers.containsKey(tagName)) {
                            try {
                                Constructor<? extends Key> keyMaker = sKeyMakers.get(tagName);
                                if (keyMaker != null) {
                                    key = keyMaker.newInstance(new Object[0]);
                                    key.load(context, Xml.asAttributeSet(parser));
                                    addKey(key);
                                    break;
                                } else {
                                    throw new NullPointerException("Keymaker for " + tagName + " not found");
                                    break;
                                }
                            } catch (Exception e) {
                                Log.e(TAG, "unable to create ", e);
                                break;
                            }
                        } else if (tagName.equalsIgnoreCase("CustomAttribute")) {
                            if (key != null && key.mCustomConstraints != null) {
                                ConstraintAttribute.parse(context, parser, key.mCustomConstraints);
                                break;
                            }
                        } else if (tagName.equalsIgnoreCase("CustomMethod") && key != null && key.mCustomConstraints != null) {
                            ConstraintAttribute.parse(context, parser, key.mCustomConstraints);
                            break;
                        }
                        break;
                    case 3:
                        if (ViewTransition.KEY_FRAME_SET_TAG.equals(parser.getName())) {
                            return;
                        }
                        break;
                }
                eventType = parser.next();
            }
        } catch (IOException e2) {
            e2.printStackTrace();
        } catch (XmlPullParserException e3) {
            e3.printStackTrace();
        }
    }

    public void addAllFrames(MotionController motionController) {
        ArrayList<Key> list = this.mFramesMap.get(-1);
        if (list != null) {
            motionController.addKeys(list);
        }
    }

    public void addFrames(MotionController motionController) {
        ArrayList<Key> list = this.mFramesMap.get(Integer.valueOf(motionController.mId));
        if (list != null) {
            motionController.addKeys(list);
        }
        ArrayList<Key> list2 = this.mFramesMap.get(-1);
        if (list2 != null) {
            Iterator<Key> it = list2.iterator();
            while (it.hasNext()) {
                Key key = it.next();
                String tag = ((ConstraintLayout.LayoutParams) motionController.mView.getLayoutParams()).constraintTag;
                if (key.matches(tag)) {
                    motionController.addKey(key);
                }
            }
        }
    }

    static String name(int viewId, Context context) {
        return context.getResources().getResourceEntryName(viewId);
    }

    public Set<Integer> getKeys() {
        return this.mFramesMap.keySet();
    }

    public ArrayList<Key> getKeyFramesForView(int id) {
        return this.mFramesMap.get(Integer.valueOf(id));
    }
}
