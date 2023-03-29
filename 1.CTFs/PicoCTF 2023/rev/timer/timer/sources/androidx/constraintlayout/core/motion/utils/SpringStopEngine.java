package androidx.constraintlayout.core.motion.utils;
/* loaded from: classes.dex */
public class SpringStopEngine implements StopEngine {
    private static final double UNSET = Double.MAX_VALUE;
    private float mLastTime;
    private double mLastVelocity;
    private float mMass;
    private float mPos;
    private double mStiffness;
    private float mStopThreshold;
    private double mTargetPos;
    private float mV;
    double mDamping = 0.5d;
    private boolean mInitialized = false;
    private int mBoundaryMode = 0;

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public String debug(String desc, float time) {
        return null;
    }

    void log(String str) {
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String line = ".(" + s.getFileName() + ":" + s.getLineNumber() + ") " + s.getMethodName() + "() ";
        System.out.println(line + str);
    }

    public void springConfig(float currentPos, float target, float currentVelocity, float mass, float stiffness, float damping, float stopThreshold, int boundaryMode) {
        this.mTargetPos = target;
        this.mDamping = damping;
        this.mInitialized = false;
        this.mPos = currentPos;
        this.mLastVelocity = currentVelocity;
        this.mStiffness = stiffness;
        this.mMass = mass;
        this.mStopThreshold = stopThreshold;
        this.mBoundaryMode = boundaryMode;
        this.mLastTime = 0.0f;
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getVelocity(float t) {
        return this.mV;
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getInterpolation(float time) {
        compute(time - this.mLastTime);
        this.mLastTime = time;
        return this.mPos;
    }

    public float getAcceleration() {
        double k = this.mStiffness;
        double c = this.mDamping;
        double x = this.mPos - this.mTargetPos;
        return ((float) (((-k) * x) - (this.mV * c))) / this.mMass;
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getVelocity() {
        return 0.0f;
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public boolean isStopped() {
        double x = this.mPos - this.mTargetPos;
        double k = this.mStiffness;
        double v = this.mV;
        double m = this.mMass;
        double energy = (v * v * m) + (k * x * x);
        double max_def = Math.sqrt(energy / k);
        return max_def <= ((double) this.mStopThreshold);
    }

    private void compute(double dt) {
        double k = this.mStiffness;
        double c = this.mDamping;
        int overSample = (int) ((9.0d / ((Math.sqrt(this.mStiffness / this.mMass) * dt) * 4.0d)) + 1.0d);
        double dt2 = dt / overSample;
        int i = 0;
        while (i < overSample) {
            float f = this.mPos;
            double d = this.mTargetPos;
            double x = f - d;
            double d2 = (-k) * x;
            int overSample2 = overSample;
            float f2 = this.mV;
            double x2 = f2;
            double d3 = d2 - (x2 * c);
            float f3 = this.mMass;
            double c2 = c;
            double c3 = f3;
            double a = d3 / c3;
            double avgV = f2 + ((a * dt2) / 2.0d);
            double a2 = f;
            double avgX = (a2 + ((dt2 * avgV) / 2.0d)) - d;
            double d4 = ((-avgX) * k) - (avgV * c2);
            double k2 = k;
            double k3 = f3;
            double a3 = d4 / k3;
            double dv = a3 * dt2;
            float f4 = (float) (f2 + dv);
            this.mV = f4;
            float f5 = (float) (f + ((f2 + (dv / 2.0d)) * dt2));
            this.mPos = f5;
            int i2 = this.mBoundaryMode;
            if (i2 > 0) {
                if (f5 < 0.0f && (i2 & 1) == 1) {
                    this.mPos = -f5;
                    this.mV = -f4;
                }
                float f6 = this.mPos;
                if (f6 > 1.0f && (i2 & 2) == 2) {
                    this.mPos = 2.0f - f6;
                    this.mV = -this.mV;
                }
            }
            i++;
            overSample = overSample2;
            c = c2;
            k = k2;
        }
    }
}
