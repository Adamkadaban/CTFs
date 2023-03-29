package androidx.constraintlayout.motion.widget;
/* compiled from: DesignTool.java */
/* loaded from: classes.dex */
interface ProxyInterface {
    int designAccess(int cmd, String type, Object viewObject, float[] in, int inLength, float[] out, int outLength);

    float getKeyFramePosition(Object view, int type, float x, float y);

    Object getKeyframeAtLocation(Object viewObject, float x, float y);

    Boolean getPositionKeyframe(Object keyFrame, Object view, float x, float y, String[] attribute, float[] value);

    long getTransitionTimeMs();

    void setAttributes(int dpi, String constraintSetId, Object opaqueView, Object opaqueAttributes);

    void setKeyFrame(Object view, int position, String name, Object value);

    boolean setKeyFramePosition(Object view, int position, int type, float x, float y);

    void setToolPosition(float position);
}
