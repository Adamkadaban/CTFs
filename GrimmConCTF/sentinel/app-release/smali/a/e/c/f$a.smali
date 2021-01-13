.class public La/e/c/f$a;
.super Landroidx/constraintlayout/widget/ConstraintLayout$a;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/e/c/f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field public n0:F

.field public o0:Z

.field public p0:F

.field public q0:F

.field public r0:F

.field public s0:F

.field public t0:F

.field public u0:F

.field public v0:F

.field public w0:F

.field public x0:F

.field public y0:F

.field public z0:F


# direct methods
.method public constructor <init>(II)V
    .locals 0

    invoke-direct {p0, p1, p2}, Landroidx/constraintlayout/widget/ConstraintLayout$a;-><init>(II)V

    const/high16 p1, 0x3f800000    # 1.0f

    iput p1, p0, La/e/c/f$a;->n0:F

    const/4 p2, 0x0

    iput-boolean p2, p0, La/e/c/f$a;->o0:Z

    const/4 p2, 0x0

    iput p2, p0, La/e/c/f$a;->p0:F

    iput p2, p0, La/e/c/f$a;->q0:F

    iput p2, p0, La/e/c/f$a;->r0:F

    iput p2, p0, La/e/c/f$a;->s0:F

    iput p1, p0, La/e/c/f$a;->t0:F

    iput p1, p0, La/e/c/f$a;->u0:F

    iput p2, p0, La/e/c/f$a;->v0:F

    iput p2, p0, La/e/c/f$a;->w0:F

    iput p2, p0, La/e/c/f$a;->x0:F

    iput p2, p0, La/e/c/f$a;->y0:F

    iput p2, p0, La/e/c/f$a;->z0:F

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 3

    invoke-direct {p0, p1, p2}, Landroidx/constraintlayout/widget/ConstraintLayout$a;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/high16 v0, 0x3f800000    # 1.0f

    iput v0, p0, La/e/c/f$a;->n0:F

    const/4 v1, 0x0

    iput-boolean v1, p0, La/e/c/f$a;->o0:Z

    const/4 v2, 0x0

    iput v2, p0, La/e/c/f$a;->p0:F

    iput v2, p0, La/e/c/f$a;->q0:F

    iput v2, p0, La/e/c/f$a;->r0:F

    iput v2, p0, La/e/c/f$a;->s0:F

    iput v0, p0, La/e/c/f$a;->t0:F

    iput v0, p0, La/e/c/f$a;->u0:F

    iput v2, p0, La/e/c/f$a;->v0:F

    iput v2, p0, La/e/c/f$a;->w0:F

    iput v2, p0, La/e/c/f$a;->x0:F

    iput v2, p0, La/e/c/f$a;->y0:F

    iput v2, p0, La/e/c/f$a;->z0:F

    sget-object v0, La/e/c/k;->ConstraintSet:[I

    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result p2

    :goto_0
    if-ge v1, p2, :cond_c

    invoke-virtual {p1, v1}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v0

    sget v2, La/e/c/k;->ConstraintSet_android_alpha:I

    if-ne v0, v2, :cond_0

    iget v2, p0, La/e/c/f$a;->n0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->n0:F

    goto/16 :goto_1

    :cond_0
    sget v2, La/e/c/k;->ConstraintSet_android_elevation:I

    if-ne v0, v2, :cond_1

    iget v2, p0, La/e/c/f$a;->p0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->p0:F

    const/4 v0, 0x1

    iput-boolean v0, p0, La/e/c/f$a;->o0:Z

    goto/16 :goto_1

    :cond_1
    sget v2, La/e/c/k;->ConstraintSet_android_rotationX:I

    if-ne v0, v2, :cond_2

    iget v2, p0, La/e/c/f$a;->r0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->r0:F

    goto/16 :goto_1

    :cond_2
    sget v2, La/e/c/k;->ConstraintSet_android_rotationY:I

    if-ne v0, v2, :cond_3

    iget v2, p0, La/e/c/f$a;->s0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->s0:F

    goto/16 :goto_1

    :cond_3
    sget v2, La/e/c/k;->ConstraintSet_android_rotation:I

    if-ne v0, v2, :cond_4

    iget v2, p0, La/e/c/f$a;->q0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->q0:F

    goto :goto_1

    :cond_4
    sget v2, La/e/c/k;->ConstraintSet_android_scaleX:I

    if-ne v0, v2, :cond_5

    iget v2, p0, La/e/c/f$a;->t0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->t0:F

    goto :goto_1

    :cond_5
    sget v2, La/e/c/k;->ConstraintSet_android_scaleY:I

    if-ne v0, v2, :cond_6

    iget v2, p0, La/e/c/f$a;->u0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->u0:F

    goto :goto_1

    :cond_6
    sget v2, La/e/c/k;->ConstraintSet_android_transformPivotX:I

    if-ne v0, v2, :cond_7

    iget v2, p0, La/e/c/f$a;->v0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->v0:F

    goto :goto_1

    :cond_7
    sget v2, La/e/c/k;->ConstraintSet_android_transformPivotY:I

    if-ne v0, v2, :cond_8

    iget v2, p0, La/e/c/f$a;->w0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->w0:F

    goto :goto_1

    :cond_8
    sget v2, La/e/c/k;->ConstraintSet_android_translationX:I

    if-ne v0, v2, :cond_9

    iget v2, p0, La/e/c/f$a;->x0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->x0:F

    goto :goto_1

    :cond_9
    sget v2, La/e/c/k;->ConstraintSet_android_translationY:I

    if-ne v0, v2, :cond_a

    iget v2, p0, La/e/c/f$a;->y0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->y0:F

    goto :goto_1

    :cond_a
    sget v2, La/e/c/k;->ConstraintSet_android_translationZ:I

    if-ne v0, v2, :cond_b

    iget v2, p0, La/e/c/f$a;->z0:F

    invoke-virtual {p1, v0, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v0

    iput v0, p0, La/e/c/f$a;->z0:F

    :cond_b
    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto/16 :goto_0

    :cond_c
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    return-void
.end method
