package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.state.helpers.AlignHorizontallyReference;
import androidx.constraintlayout.core.state.helpers.AlignVerticallyReference;
import androidx.constraintlayout.core.state.helpers.BarrierReference;
import androidx.constraintlayout.core.state.helpers.GuidelineReference;
import androidx.constraintlayout.core.state.helpers.HorizontalChainReference;
import androidx.constraintlayout.core.state.helpers.VerticalChainReference;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.ConstraintWidgetContainer;
import androidx.constraintlayout.core.widgets.HelperWidget;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
/* loaded from: classes.dex */
public class State {
    static final int CONSTRAINT_RATIO = 2;
    static final int CONSTRAINT_SPREAD = 0;
    static final int CONSTRAINT_WRAP = 1;
    public static final Integer PARENT = 0;
    static final int UNKNOWN = -1;
    public final ConstraintReference mParent;
    private int numHelpers;
    protected HashMap<Object, Reference> mReferences = new HashMap<>();
    protected HashMap<Object, HelperReference> mHelperReferences = new HashMap<>();
    HashMap<String, ArrayList<String>> mTags = new HashMap<>();

    /* loaded from: classes.dex */
    public enum Chain {
        SPREAD,
        SPREAD_INSIDE,
        PACKED
    }

    /* loaded from: classes.dex */
    public enum Constraint {
        LEFT_TO_LEFT,
        LEFT_TO_RIGHT,
        RIGHT_TO_LEFT,
        RIGHT_TO_RIGHT,
        START_TO_START,
        START_TO_END,
        END_TO_START,
        END_TO_END,
        TOP_TO_TOP,
        TOP_TO_BOTTOM,
        BOTTOM_TO_TOP,
        BOTTOM_TO_BOTTOM,
        BASELINE_TO_BASELINE,
        BASELINE_TO_TOP,
        BASELINE_TO_BOTTOM,
        CENTER_HORIZONTALLY,
        CENTER_VERTICALLY,
        CIRCULAR_CONSTRAINT
    }

    /* loaded from: classes.dex */
    public enum Direction {
        LEFT,
        RIGHT,
        START,
        END,
        TOP,
        BOTTOM
    }

    /* loaded from: classes.dex */
    public enum Helper {
        HORIZONTAL_CHAIN,
        VERTICAL_CHAIN,
        ALIGN_HORIZONTALLY,
        ALIGN_VERTICALLY,
        BARRIER,
        LAYER,
        FLOW
    }

    public State() {
        ConstraintReference constraintReference = new ConstraintReference(this);
        this.mParent = constraintReference;
        this.numHelpers = 0;
        this.mReferences.put(PARENT, constraintReference);
    }

    public void reset() {
        this.mHelperReferences.clear();
        this.mTags.clear();
    }

    public int convertDimension(Object value) {
        if (value instanceof Float) {
            return ((Float) value).intValue();
        }
        if (value instanceof Integer) {
            return ((Integer) value).intValue();
        }
        return 0;
    }

    public ConstraintReference createConstraintReference(Object key) {
        return new ConstraintReference(this);
    }

    public boolean sameFixedWidth(int width) {
        return this.mParent.getWidth().equalsFixedValue(width);
    }

    public boolean sameFixedHeight(int height) {
        return this.mParent.getHeight().equalsFixedValue(height);
    }

    public State width(Dimension dimension) {
        return setWidth(dimension);
    }

    public State height(Dimension dimension) {
        return setHeight(dimension);
    }

    public State setWidth(Dimension dimension) {
        this.mParent.setWidth(dimension);
        return this;
    }

    public State setHeight(Dimension dimension) {
        this.mParent.setHeight(dimension);
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Reference reference(Object key) {
        return this.mReferences.get(key);
    }

    public ConstraintReference constraints(Object key) {
        Reference reference = this.mReferences.get(key);
        if (reference == null) {
            reference = createConstraintReference(key);
            this.mReferences.put(key, reference);
            reference.setKey(key);
        }
        if (reference instanceof ConstraintReference) {
            return (ConstraintReference) reference;
        }
        return null;
    }

    private String createHelperKey() {
        StringBuilder sb = new StringBuilder();
        sb.append("__HELPER_KEY_");
        int i = this.numHelpers;
        this.numHelpers = i + 1;
        sb.append(i);
        sb.append("__");
        return sb.toString();
    }

    public HelperReference helper(Object key, Helper type) {
        if (key == null) {
            key = createHelperKey();
        }
        HelperReference reference = this.mHelperReferences.get(key);
        if (reference == null) {
            switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$core$state$State$Helper[type.ordinal()]) {
                case 1:
                    reference = new HorizontalChainReference(this);
                    break;
                case 2:
                    reference = new VerticalChainReference(this);
                    break;
                case 3:
                    reference = new AlignHorizontallyReference(this);
                    break;
                case 4:
                    reference = new AlignVerticallyReference(this);
                    break;
                case 5:
                    reference = new BarrierReference(this);
                    break;
                default:
                    reference = new HelperReference(this, type);
                    break;
            }
            reference.setKey(key);
            this.mHelperReferences.put(key, reference);
        }
        return reference;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: androidx.constraintlayout.core.state.State$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$core$state$State$Helper;

        static {
            int[] iArr = new int[Helper.values().length];
            $SwitchMap$androidx$constraintlayout$core$state$State$Helper = iArr;
            try {
                iArr[Helper.HORIZONTAL_CHAIN.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$state$State$Helper[Helper.VERTICAL_CHAIN.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$state$State$Helper[Helper.ALIGN_HORIZONTALLY.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$state$State$Helper[Helper.ALIGN_VERTICALLY.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$core$state$State$Helper[Helper.BARRIER.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    public GuidelineReference horizontalGuideline(Object key) {
        return guideline(key, 0);
    }

    public GuidelineReference verticalGuideline(Object key) {
        return guideline(key, 1);
    }

    public GuidelineReference guideline(Object key, int orientation) {
        ConstraintReference reference = constraints(key);
        if (reference.getFacade() == null || !(reference.getFacade() instanceof GuidelineReference)) {
            GuidelineReference guidelineReference = new GuidelineReference(this);
            guidelineReference.setOrientation(orientation);
            guidelineReference.setKey(key);
            reference.setFacade(guidelineReference);
        }
        return (GuidelineReference) reference.getFacade();
    }

    public BarrierReference barrier(Object key, Direction direction) {
        ConstraintReference reference = constraints(key);
        if (reference.getFacade() == null || !(reference.getFacade() instanceof BarrierReference)) {
            BarrierReference barrierReference = new BarrierReference(this);
            barrierReference.setBarrierDirection(direction);
            reference.setFacade(barrierReference);
        }
        return (BarrierReference) reference.getFacade();
    }

    public VerticalChainReference verticalChain() {
        return (VerticalChainReference) helper(null, Helper.VERTICAL_CHAIN);
    }

    public VerticalChainReference verticalChain(Object... references) {
        VerticalChainReference reference = (VerticalChainReference) helper(null, Helper.VERTICAL_CHAIN);
        reference.add(references);
        return reference;
    }

    public HorizontalChainReference horizontalChain() {
        return (HorizontalChainReference) helper(null, Helper.HORIZONTAL_CHAIN);
    }

    public HorizontalChainReference horizontalChain(Object... references) {
        HorizontalChainReference reference = (HorizontalChainReference) helper(null, Helper.HORIZONTAL_CHAIN);
        reference.add(references);
        return reference;
    }

    public AlignHorizontallyReference centerHorizontally(Object... references) {
        AlignHorizontallyReference reference = (AlignHorizontallyReference) helper(null, Helper.ALIGN_HORIZONTALLY);
        reference.add(references);
        return reference;
    }

    public AlignVerticallyReference centerVertically(Object... references) {
        AlignVerticallyReference reference = (AlignVerticallyReference) helper(null, Helper.ALIGN_VERTICALLY);
        reference.add(references);
        return reference;
    }

    public void directMapping() {
        for (Object key : this.mReferences.keySet()) {
            Reference ref = constraints(key);
            if (ref instanceof ConstraintReference) {
                ConstraintReference reference = (ConstraintReference) ref;
                reference.setView(key);
            }
        }
    }

    public void map(Object key, Object view) {
        Reference ref = constraints(key);
        if (ref instanceof ConstraintReference) {
            ConstraintReference reference = (ConstraintReference) ref;
            reference.setView(view);
        }
    }

    public void setTag(String key, String tag) {
        ArrayList<String> list;
        Reference ref = constraints(key);
        if (ref instanceof ConstraintReference) {
            ConstraintReference reference = (ConstraintReference) ref;
            reference.setTag(tag);
            if (!this.mTags.containsKey(tag)) {
                list = new ArrayList<>();
                this.mTags.put(tag, list);
            } else {
                ArrayList<String> list2 = this.mTags.get(tag);
                list = list2;
            }
            list.add(key);
        }
    }

    public ArrayList<String> getIdsForTag(String tag) {
        if (this.mTags.containsKey(tag)) {
            return this.mTags.get(tag);
        }
        return null;
    }

    public void apply(ConstraintWidgetContainer container) {
        HelperReference helperReference;
        HelperWidget helperWidget;
        HelperWidget helperWidget2;
        container.removeAllChildren();
        this.mParent.getWidth().apply(this, container, 0);
        this.mParent.getHeight().apply(this, container, 1);
        for (Object key : this.mHelperReferences.keySet()) {
            HelperWidget helperWidget3 = this.mHelperReferences.get(key).getHelperWidget();
            if (helperWidget3 != null) {
                Reference constraintReference = this.mReferences.get(key);
                if (constraintReference == null) {
                    constraintReference = constraints(key);
                }
                constraintReference.setConstraintWidget(helperWidget3);
            }
        }
        for (Object key2 : this.mReferences.keySet()) {
            Reference reference = this.mReferences.get(key2);
            if (reference != this.mParent && (reference.getFacade() instanceof HelperReference) && (helperWidget2 = ((HelperReference) reference.getFacade()).getHelperWidget()) != null) {
                Reference constraintReference2 = this.mReferences.get(key2);
                if (constraintReference2 == null) {
                    constraintReference2 = constraints(key2);
                }
                constraintReference2.setConstraintWidget(helperWidget2);
            }
        }
        for (Object key3 : this.mReferences.keySet()) {
            Reference reference2 = this.mReferences.get(key3);
            if (reference2 != this.mParent) {
                ConstraintWidget widget = reference2.getConstraintWidget();
                widget.setDebugName(reference2.getKey().toString());
                widget.setParent(null);
                if (reference2.getFacade() instanceof GuidelineReference) {
                    reference2.apply();
                }
                container.add(widget);
            } else {
                reference2.setConstraintWidget(container);
            }
        }
        for (Object key4 : this.mHelperReferences.keySet()) {
            HelperReference reference3 = this.mHelperReferences.get(key4);
            if (reference3.getHelperWidget() != null) {
                Iterator<Object> it = reference3.mReferences.iterator();
                while (it.hasNext()) {
                    reference3.getHelperWidget().add(this.mReferences.get(it.next()).getConstraintWidget());
                }
                reference3.apply();
            } else {
                reference3.apply();
            }
        }
        for (Object key5 : this.mReferences.keySet()) {
            Reference reference4 = this.mReferences.get(key5);
            if (reference4 != this.mParent && (reference4.getFacade() instanceof HelperReference) && (helperWidget = (helperReference = (HelperReference) reference4.getFacade()).getHelperWidget()) != null) {
                Iterator<Object> it2 = helperReference.mReferences.iterator();
                while (it2.hasNext()) {
                    Object keyRef = it2.next();
                    Reference constraintReference3 = this.mReferences.get(keyRef);
                    if (constraintReference3 != null) {
                        helperWidget.add(constraintReference3.getConstraintWidget());
                    } else if (keyRef instanceof Reference) {
                        helperWidget.add(((Reference) keyRef).getConstraintWidget());
                    } else {
                        PrintStream printStream = System.out;
                        printStream.println("couldn't find reference for " + keyRef);
                    }
                }
                reference4.apply();
            }
        }
        for (Object key6 : this.mReferences.keySet()) {
            Reference reference5 = this.mReferences.get(key6);
            reference5.apply();
            ConstraintWidget widget2 = reference5.getConstraintWidget();
            if (widget2 != null && key6 != null) {
                widget2.stringId = key6.toString();
            }
        }
    }
}
