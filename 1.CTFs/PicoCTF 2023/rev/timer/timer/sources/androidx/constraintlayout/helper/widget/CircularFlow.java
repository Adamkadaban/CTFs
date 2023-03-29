package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.R;
import androidx.constraintlayout.widget.VirtualLayout;
import java.util.Arrays;
/* loaded from: classes.dex */
public class CircularFlow extends VirtualLayout {
    private static final String TAG = "CircularFlow";
    private float[] mAngles;
    ConstraintLayout mContainer;
    private int mCountAngle;
    private int mCountRadius;
    private int[] mRadius;
    private String mReferenceAngles;
    private Float mReferenceDefaultAngle;
    private Integer mReferenceDefaultRadius;
    private String mReferenceRadius;
    int mViewCenter;
    private static int DEFAULT_RADIUS = 0;
    private static float DEFAULT_ANGLE = 0.0f;

    public CircularFlow(Context context) {
        super(context);
    }

    public CircularFlow(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public CircularFlow(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    public int[] getRadius() {
        return Arrays.copyOf(this.mRadius, this.mCountRadius);
    }

    public float[] getAngles() {
        return Arrays.copyOf(this.mAngles, this.mCountAngle);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.VirtualLayout, androidx.constraintlayout.widget.ConstraintHelper
    public void init(AttributeSet attrs) {
        super.init(attrs);
        if (attrs != null) {
            TypedArray a = getContext().obtainStyledAttributes(attrs, R.styleable.ConstraintLayout_Layout);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.ConstraintLayout_Layout_circularflow_viewCenter) {
                    this.mViewCenter = a.getResourceId(attr, 0);
                } else if (attr == R.styleable.ConstraintLayout_Layout_circularflow_angles) {
                    String string = a.getString(attr);
                    this.mReferenceAngles = string;
                    setAngles(string);
                } else if (attr == R.styleable.ConstraintLayout_Layout_circularflow_radiusInDP) {
                    String string2 = a.getString(attr);
                    this.mReferenceRadius = string2;
                    setRadius(string2);
                } else if (attr == R.styleable.ConstraintLayout_Layout_circularflow_defaultAngle) {
                    Float valueOf = Float.valueOf(a.getFloat(attr, DEFAULT_ANGLE));
                    this.mReferenceDefaultAngle = valueOf;
                    setDefaultAngle(valueOf.floatValue());
                } else if (attr == R.styleable.ConstraintLayout_Layout_circularflow_defaultRadius) {
                    Integer valueOf2 = Integer.valueOf(a.getDimensionPixelSize(attr, DEFAULT_RADIUS));
                    this.mReferenceDefaultRadius = valueOf2;
                    setDefaultRadius(valueOf2.intValue());
                }
            }
            a.recycle();
        }
    }

    @Override // androidx.constraintlayout.widget.VirtualLayout, androidx.constraintlayout.widget.ConstraintHelper, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        String str = this.mReferenceAngles;
        if (str != null) {
            this.mAngles = new float[1];
            setAngles(str);
        }
        String str2 = this.mReferenceRadius;
        if (str2 != null) {
            this.mRadius = new int[1];
            setRadius(str2);
        }
        Float f = this.mReferenceDefaultAngle;
        if (f != null) {
            setDefaultAngle(f.floatValue());
        }
        Integer num = this.mReferenceDefaultRadius;
        if (num != null) {
            setDefaultRadius(num.intValue());
        }
        anchorReferences();
    }

    private void anchorReferences() {
        this.mContainer = (ConstraintLayout) getParent();
        for (int i = 0; i < this.mCount; i++) {
            View view = this.mContainer.getViewById(this.mIds[i]);
            if (view != null) {
                int radius = DEFAULT_RADIUS;
                float angle = DEFAULT_ANGLE;
                int[] iArr = this.mRadius;
                if (iArr != null && i < iArr.length) {
                    radius = iArr[i];
                } else {
                    Integer num = this.mReferenceDefaultRadius;
                    if (num == null || num.intValue() == -1) {
                        Log.e(TAG, "Added radius to view with id: " + this.mMap.get(Integer.valueOf(view.getId())));
                    } else {
                        this.mCountRadius++;
                        if (this.mRadius == null) {
                            this.mRadius = new int[1];
                        }
                        int[] radius2 = getRadius();
                        this.mRadius = radius2;
                        radius2[this.mCountRadius - 1] = radius;
                    }
                }
                float[] fArr = this.mAngles;
                if (fArr != null && i < fArr.length) {
                    angle = fArr[i];
                } else {
                    Float f = this.mReferenceDefaultAngle;
                    if (f == null || f.floatValue() == -1.0f) {
                        Log.e(TAG, "Added angle to view with id: " + this.mMap.get(Integer.valueOf(view.getId())));
                    } else {
                        this.mCountAngle++;
                        if (this.mAngles == null) {
                            this.mAngles = new float[1];
                        }
                        float[] angles = getAngles();
                        this.mAngles = angles;
                        angles[this.mCountAngle - 1] = angle;
                    }
                }
                ConstraintLayout.LayoutParams params = (ConstraintLayout.LayoutParams) view.getLayoutParams();
                params.circleAngle = angle;
                params.circleConstraint = this.mViewCenter;
                params.circleRadius = radius;
                view.setLayoutParams(params);
            }
        }
        applyLayoutFeatures();
    }

    public void addViewToCircularFlow(View view, int radius, float angle) {
        if (containsId(view.getId())) {
            return;
        }
        addView(view);
        this.mCountAngle++;
        float[] angles = getAngles();
        this.mAngles = angles;
        angles[this.mCountAngle - 1] = angle;
        this.mCountRadius++;
        int[] radius2 = getRadius();
        this.mRadius = radius2;
        radius2[this.mCountRadius - 1] = (int) (radius * this.myContext.getResources().getDisplayMetrics().density);
        anchorReferences();
    }

    public void updateRadius(View view, int radius) {
        if (!isUpdatable(view)) {
            Log.e(TAG, "It was not possible to update radius to view with id: " + view.getId());
            return;
        }
        int indexView = indexFromId(view.getId());
        if (indexView > this.mRadius.length) {
            return;
        }
        int[] radius2 = getRadius();
        this.mRadius = radius2;
        radius2[indexView] = (int) (radius * this.myContext.getResources().getDisplayMetrics().density);
        anchorReferences();
    }

    public void updateAngle(View view, float angle) {
        if (!isUpdatable(view)) {
            Log.e(TAG, "It was not possible to update angle to view with id: " + view.getId());
            return;
        }
        int indexView = indexFromId(view.getId());
        if (indexView > this.mAngles.length) {
            return;
        }
        float[] angles = getAngles();
        this.mAngles = angles;
        angles[indexView] = angle;
        anchorReferences();
    }

    public void updateReference(View view, int radius, float angle) {
        if (!isUpdatable(view)) {
            Log.e(TAG, "It was not possible to update radius and angle to view with id: " + view.getId());
            return;
        }
        int indexView = indexFromId(view.getId());
        if (getAngles().length > indexView) {
            float[] angles = getAngles();
            this.mAngles = angles;
            angles[indexView] = angle;
        }
        if (getRadius().length > indexView) {
            int[] radius2 = getRadius();
            this.mRadius = radius2;
            radius2[indexView] = (int) (radius * this.myContext.getResources().getDisplayMetrics().density);
        }
        anchorReferences();
    }

    public void setDefaultAngle(float angle) {
        DEFAULT_ANGLE = angle;
    }

    public void setDefaultRadius(int radius) {
        DEFAULT_RADIUS = radius;
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public int removeView(View view) {
        int index = super.removeView(view);
        if (index == -1) {
            return index;
        }
        ConstraintSet c = new ConstraintSet();
        c.clone(this.mContainer);
        c.clear(view.getId(), 8);
        c.applyTo(this.mContainer);
        float[] fArr = this.mAngles;
        if (index < fArr.length) {
            this.mAngles = removeAngle(fArr, index);
            this.mCountAngle--;
        }
        int[] iArr = this.mRadius;
        if (index < iArr.length) {
            this.mRadius = removeRadius(iArr, index);
            this.mCountRadius--;
        }
        anchorReferences();
        return index;
    }

    private float[] removeAngle(float[] angles, int index) {
        if (angles == null || index < 0 || index >= this.mCountAngle) {
            return angles;
        }
        return removeElementFromArray(angles, index);
    }

    private int[] removeRadius(int[] radius, int index) {
        if (radius == null || index < 0 || index >= this.mCountRadius) {
            return radius;
        }
        return removeElementFromArray(radius, index);
    }

    private void setAngles(String idList) {
        if (idList == null) {
            return;
        }
        int begin = 0;
        this.mCountAngle = 0;
        while (true) {
            int end = idList.indexOf(44, begin);
            if (end == -1) {
                addAngle(idList.substring(begin).trim());
                return;
            } else {
                addAngle(idList.substring(begin, end).trim());
                begin = end + 1;
            }
        }
    }

    private void setRadius(String idList) {
        if (idList == null) {
            return;
        }
        int begin = 0;
        this.mCountRadius = 0;
        while (true) {
            int end = idList.indexOf(44, begin);
            if (end == -1) {
                addRadius(idList.substring(begin).trim());
                return;
            } else {
                addRadius(idList.substring(begin, end).trim());
                begin = end + 1;
            }
        }
    }

    private void addAngle(String angleString) {
        float[] fArr;
        if (angleString == null || angleString.length() == 0 || this.myContext == null || (fArr = this.mAngles) == null) {
            return;
        }
        if (this.mCountAngle + 1 > fArr.length) {
            this.mAngles = Arrays.copyOf(fArr, fArr.length + 1);
        }
        this.mAngles[this.mCountAngle] = Integer.parseInt(angleString);
        this.mCountAngle++;
    }

    private void addRadius(String radiusString) {
        int[] iArr;
        if (radiusString == null || radiusString.length() == 0 || this.myContext == null || (iArr = this.mRadius) == null) {
            return;
        }
        if (this.mCountRadius + 1 > iArr.length) {
            this.mRadius = Arrays.copyOf(iArr, iArr.length + 1);
        }
        this.mRadius[this.mCountRadius] = (int) (Integer.parseInt(radiusString) * this.myContext.getResources().getDisplayMetrics().density);
        this.mCountRadius++;
    }

    public static int[] removeElementFromArray(int[] array, int index) {
        int[] newArray = new int[array.length - 1];
        int k = 0;
        for (int i = 0; i < array.length; i++) {
            if (i != index) {
                newArray[k] = array[i];
                k++;
            }
        }
        return newArray;
    }

    public static float[] removeElementFromArray(float[] array, int index) {
        float[] newArray = new float[array.length - 1];
        int k = 0;
        for (int i = 0; i < array.length; i++) {
            if (i != index) {
                newArray[k] = array[i];
                k++;
            }
        }
        return newArray;
    }

    public boolean isUpdatable(View view) {
        if (containsId(view.getId())) {
            int indexView = indexFromId(view.getId());
            return indexView != -1;
        }
        return false;
    }
}
