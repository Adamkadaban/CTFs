package com.google.android.material.shape;
@Deprecated
/* loaded from: classes.dex */
public class ShapePathModel extends ShapeAppearanceModel {
    @Deprecated
    public void setAllCorners(CornerTreatment cornerTreatment) {
        this.topLeftCorner = cornerTreatment;
        this.topRightCorner = cornerTreatment;
        this.bottomRightCorner = cornerTreatment;
        this.bottomLeftCorner = cornerTreatment;
    }

    @Deprecated
    public void setAllEdges(EdgeTreatment edgeTreatment) {
        this.leftEdge = edgeTreatment;
        this.topEdge = edgeTreatment;
        this.rightEdge = edgeTreatment;
        this.bottomEdge = edgeTreatment;
    }

    @Deprecated
    public void setCornerTreatments(CornerTreatment topLeftCorner, CornerTreatment topRightCorner, CornerTreatment bottomRightCorner, CornerTreatment bottomLeftCorner) {
        this.topLeftCorner = topLeftCorner;
        this.topRightCorner = topRightCorner;
        this.bottomRightCorner = bottomRightCorner;
        this.bottomLeftCorner = bottomLeftCorner;
    }

    @Deprecated
    public void setEdgeTreatments(EdgeTreatment leftEdge, EdgeTreatment topEdge, EdgeTreatment rightEdge, EdgeTreatment bottomEdge) {
        this.leftEdge = leftEdge;
        this.topEdge = topEdge;
        this.rightEdge = rightEdge;
        this.bottomEdge = bottomEdge;
    }

    @Deprecated
    public void setTopLeftCorner(CornerTreatment topLeftCorner) {
        this.topLeftCorner = topLeftCorner;
    }

    @Deprecated
    public void setTopRightCorner(CornerTreatment topRightCorner) {
        this.topRightCorner = topRightCorner;
    }

    @Deprecated
    public void setBottomRightCorner(CornerTreatment bottomRightCorner) {
        this.bottomRightCorner = bottomRightCorner;
    }

    @Deprecated
    public void setBottomLeftCorner(CornerTreatment bottomLeftCorner) {
        this.bottomLeftCorner = bottomLeftCorner;
    }

    @Deprecated
    public void setTopEdge(EdgeTreatment topEdge) {
        this.topEdge = topEdge;
    }

    @Deprecated
    public void setRightEdge(EdgeTreatment rightEdge) {
        this.rightEdge = rightEdge;
    }

    @Deprecated
    public void setBottomEdge(EdgeTreatment bottomEdge) {
        this.bottomEdge = bottomEdge;
    }

    @Deprecated
    public void setLeftEdge(EdgeTreatment leftEdge) {
        this.leftEdge = leftEdge;
    }
}
