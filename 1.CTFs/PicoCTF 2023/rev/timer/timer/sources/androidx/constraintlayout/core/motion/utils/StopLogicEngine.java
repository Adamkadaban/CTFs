package androidx.constraintlayout.core.motion.utils;
/* loaded from: classes.dex */
public class StopLogicEngine implements StopEngine {
    private static final float EPSILON = 1.0E-5f;
    private boolean mBackwards = false;
    private boolean mDone = false;
    private float mLastPosition;
    private int mNumberOfStages;
    private float mStage1Duration;
    private float mStage1EndPosition;
    private float mStage1Velocity;
    private float mStage2Duration;
    private float mStage2EndPosition;
    private float mStage2Velocity;
    private float mStage3Duration;
    private float mStage3EndPosition;
    private float mStage3Velocity;
    private float mStartPosition;
    private String mType;

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public String debug(String desc, float time) {
        String ret = desc + " ===== " + this.mType + "\n";
        StringBuilder sb = new StringBuilder();
        sb.append(ret);
        sb.append(desc);
        sb.append(this.mBackwards ? "backwards" : "forward ");
        sb.append(" time = ");
        sb.append(time);
        sb.append("  stages ");
        sb.append(this.mNumberOfStages);
        sb.append("\n");
        String ret2 = sb.toString();
        String ret3 = ret2 + desc + " dur " + this.mStage1Duration + " vel " + this.mStage1Velocity + " pos " + this.mStage1EndPosition + "\n";
        if (this.mNumberOfStages > 1) {
            ret3 = ret3 + desc + " dur " + this.mStage2Duration + " vel " + this.mStage2Velocity + " pos " + this.mStage2EndPosition + "\n";
        }
        if (this.mNumberOfStages > 2) {
            ret3 = ret3 + desc + " dur " + this.mStage3Duration + " vel " + this.mStage3Velocity + " pos " + this.mStage3EndPosition + "\n";
        }
        float f = this.mStage1Duration;
        if (time <= f) {
            return ret3 + desc + "stage 0\n";
        }
        int i = this.mNumberOfStages;
        if (i == 1) {
            return ret3 + desc + "end stage 0\n";
        }
        float time2 = time - f;
        float f2 = this.mStage2Duration;
        if (time2 < f2) {
            return ret3 + desc + " stage 1\n";
        } else if (i == 2) {
            return ret3 + desc + "end stage 1\n";
        } else if (time2 - f2 < this.mStage3Duration) {
            return ret3 + desc + " stage 2\n";
        } else {
            return ret3 + desc + " end stage 2\n";
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getVelocity(float x) {
        float f = this.mStage1Duration;
        if (x <= f) {
            float f2 = this.mStage1Velocity;
            return f2 + (((this.mStage2Velocity - f2) * x) / f);
        }
        int i = this.mNumberOfStages;
        if (i == 1) {
            return 0.0f;
        }
        float x2 = x - f;
        float f3 = this.mStage2Duration;
        if (x2 < f3) {
            float f4 = this.mStage2Velocity;
            return f4 + (((this.mStage3Velocity - f4) * x2) / f3);
        } else if (i == 2) {
            return this.mStage2EndPosition;
        } else {
            float x3 = x2 - f3;
            float f5 = this.mStage3Duration;
            if (x3 < f5) {
                float f6 = this.mStage3Velocity;
                return f6 - ((f6 * x3) / f5);
            }
            return this.mStage3EndPosition;
        }
    }

    private float calcY(float time) {
        this.mDone = false;
        float f = this.mStage1Duration;
        if (time <= f) {
            float f2 = this.mStage1Velocity;
            return (f2 * time) + ((((this.mStage2Velocity - f2) * time) * time) / (f * 2.0f));
        }
        int i = this.mNumberOfStages;
        if (i == 1) {
            return this.mStage1EndPosition;
        }
        float time2 = time - f;
        float f3 = this.mStage2Duration;
        if (time2 < f3) {
            float f4 = this.mStage1EndPosition;
            float f5 = this.mStage2Velocity;
            return f4 + (f5 * time2) + ((((this.mStage3Velocity - f5) * time2) * time2) / (f3 * 2.0f));
        } else if (i == 2) {
            return this.mStage2EndPosition;
        } else {
            float time3 = time2 - f3;
            float f6 = this.mStage3Duration;
            if (time3 <= f6) {
                float f7 = this.mStage2EndPosition;
                float f8 = this.mStage3Velocity;
                return (f7 + (f8 * time3)) - (((f8 * time3) * time3) / (f6 * 2.0f));
            }
            this.mDone = true;
            return this.mStage3EndPosition;
        }
    }

    public void config(float currentPos, float destination, float currentVelocity, float maxTime, float maxAcceleration, float maxVelocity) {
        this.mDone = false;
        this.mStartPosition = currentPos;
        boolean z = currentPos > destination;
        this.mBackwards = z;
        if (z) {
            setup(-currentVelocity, currentPos - destination, maxAcceleration, maxVelocity, maxTime);
        } else {
            setup(currentVelocity, destination - currentPos, maxAcceleration, maxVelocity, maxTime);
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getInterpolation(float v) {
        float y = calcY(v);
        this.mLastPosition = v;
        return this.mBackwards ? this.mStartPosition - y : this.mStartPosition + y;
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public float getVelocity() {
        return this.mBackwards ? -getVelocity(this.mLastPosition) : getVelocity(this.mLastPosition);
    }

    @Override // androidx.constraintlayout.core.motion.utils.StopEngine
    public boolean isStopped() {
        return getVelocity() < EPSILON && Math.abs(this.mStage3EndPosition - this.mLastPosition) < EPSILON;
    }

    private void setup(float velocity, float distance, float maxAcceleration, float maxVelocity, float maxTime) {
        float velocity2;
        this.mDone = false;
        if (velocity != 0.0f) {
            velocity2 = velocity;
        } else {
            velocity2 = 1.0E-4f;
        }
        this.mStage1Velocity = velocity2;
        float min_time_to_stop = velocity2 / maxAcceleration;
        float stopDistance = (min_time_to_stop * velocity2) / 2.0f;
        if (velocity2 < 0.0f) {
            float timeToZeroVelocity = (-velocity2) / maxAcceleration;
            float reversDistanceTraveled = (timeToZeroVelocity * velocity2) / 2.0f;
            float totalDistance = distance - reversDistanceTraveled;
            float peak_v = (float) Math.sqrt(maxAcceleration * totalDistance);
            if (peak_v < maxVelocity) {
                this.mType = "backward accelerate, decelerate";
                this.mNumberOfStages = 2;
                this.mStage1Velocity = velocity2;
                this.mStage2Velocity = peak_v;
                this.mStage3Velocity = 0.0f;
                float f = (peak_v - velocity2) / maxAcceleration;
                this.mStage1Duration = f;
                this.mStage2Duration = peak_v / maxAcceleration;
                this.mStage1EndPosition = ((velocity2 + peak_v) * f) / 2.0f;
                this.mStage2EndPosition = distance;
                this.mStage3EndPosition = distance;
                return;
            }
            this.mType = "backward accelerate cruse decelerate";
            this.mNumberOfStages = 3;
            this.mStage1Velocity = velocity2;
            this.mStage2Velocity = maxVelocity;
            this.mStage3Velocity = maxVelocity;
            float f2 = (maxVelocity - velocity2) / maxAcceleration;
            this.mStage1Duration = f2;
            float f3 = maxVelocity / maxAcceleration;
            this.mStage3Duration = f3;
            float accDist = ((velocity2 + maxVelocity) * f2) / 2.0f;
            float decDist = (maxVelocity * f3) / 2.0f;
            this.mStage2Duration = ((distance - accDist) - decDist) / maxVelocity;
            this.mStage1EndPosition = accDist;
            this.mStage2EndPosition = distance - decDist;
            this.mStage3EndPosition = distance;
        } else if (stopDistance >= distance) {
            this.mType = "hard stop";
            float time = (2.0f * distance) / velocity2;
            this.mNumberOfStages = 1;
            this.mStage1Velocity = velocity2;
            this.mStage2Velocity = 0.0f;
            this.mStage1EndPosition = distance;
            this.mStage1Duration = time;
        } else {
            float distance_before_break = distance - stopDistance;
            float cruseTime = distance_before_break / velocity2;
            if (cruseTime + min_time_to_stop < maxTime) {
                this.mType = "cruse decelerate";
                this.mNumberOfStages = 2;
                this.mStage1Velocity = velocity2;
                this.mStage2Velocity = velocity2;
                this.mStage3Velocity = 0.0f;
                this.mStage1EndPosition = distance_before_break;
                this.mStage2EndPosition = distance;
                this.mStage1Duration = cruseTime;
                this.mStage2Duration = velocity2 / maxAcceleration;
                return;
            }
            float peak_v2 = (float) Math.sqrt((maxAcceleration * distance) + ((velocity2 * velocity2) / 2.0f));
            this.mStage1Duration = (peak_v2 - velocity2) / maxAcceleration;
            this.mStage2Duration = peak_v2 / maxAcceleration;
            if (peak_v2 < maxVelocity) {
                this.mType = "accelerate decelerate";
                this.mNumberOfStages = 2;
                this.mStage1Velocity = velocity2;
                this.mStage2Velocity = peak_v2;
                this.mStage3Velocity = 0.0f;
                float f4 = (peak_v2 - velocity2) / maxAcceleration;
                this.mStage1Duration = f4;
                this.mStage2Duration = peak_v2 / maxAcceleration;
                this.mStage1EndPosition = ((velocity2 + peak_v2) * f4) / 2.0f;
                this.mStage2EndPosition = distance;
                return;
            }
            this.mType = "accelerate cruse decelerate";
            this.mNumberOfStages = 3;
            this.mStage1Velocity = velocity2;
            this.mStage2Velocity = maxVelocity;
            this.mStage3Velocity = maxVelocity;
            float f5 = (maxVelocity - velocity2) / maxAcceleration;
            this.mStage1Duration = f5;
            float f6 = maxVelocity / maxAcceleration;
            this.mStage3Duration = f6;
            float accDist2 = ((velocity2 + maxVelocity) * f5) / 2.0f;
            float decDist2 = (maxVelocity * f6) / 2.0f;
            this.mStage2Duration = ((distance - accDist2) - decDist2) / maxVelocity;
            this.mStage1EndPosition = accDist2;
            this.mStage2EndPosition = distance - decDist2;
            this.mStage3EndPosition = distance;
        }
    }
}
