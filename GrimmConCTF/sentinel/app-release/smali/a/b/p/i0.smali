.class public La/b/p/i0;
.super Landroid/view/ViewGroup;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/p/i0$a;
    }
.end annotation


# instance fields
.field public b:Z

.field public c:I

.field public d:I

.field public e:I

.field public f:I

.field public g:I

.field public h:F

.field public i:Z

.field public j:[I

.field public k:[I

.field public l:Landroid/graphics/drawable/Drawable;

.field public m:I

.field public n:I

.field public o:I

.field public p:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, La/b/p/i0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, La/b/p/i0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 11

    invoke-direct {p0, p1, p2, p3}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/p/i0;->b:Z

    const/4 v1, -0x1

    iput v1, p0, La/b/p/i0;->c:I

    const/4 v2, 0x0

    iput v2, p0, La/b/p/i0;->d:I

    const v3, 0x800033

    iput v3, p0, La/b/p/i0;->f:I

    sget-object v3, La/b/j;->LinearLayoutCompat:[I

    .line 1
    invoke-virtual {p1, p2, v3, p3, v2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v3

    .line 2
    sget-object v6, La/b/j;->LinearLayoutCompat:[I

    const/4 v10, 0x0

    move-object v4, p0

    move-object v5, p1

    move-object v7, p2

    move-object v8, v3

    move v9, p3

    invoke-static/range {v4 .. v10}, La/f/j/k;->t(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    sget p2, La/b/j;->LinearLayoutCompat_android_orientation:I

    .line 3
    invoke-virtual {v3, p2, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result p2

    if-ltz p2, :cond_0

    .line 4
    invoke-virtual {p0, p2}, La/b/p/i0;->setOrientation(I)V

    :cond_0
    sget p2, La/b/j;->LinearLayoutCompat_android_gravity:I

    .line 5
    invoke-virtual {v3, p2, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result p2

    if-ltz p2, :cond_1

    .line 6
    invoke-virtual {p0, p2}, La/b/p/i0;->setGravity(I)V

    :cond_1
    sget p2, La/b/j;->LinearLayoutCompat_android_baselineAligned:I

    .line 7
    invoke-virtual {v3, p2, v0}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result p2

    if-nez p2, :cond_2

    .line 8
    invoke-virtual {p0, p2}, La/b/p/i0;->setBaselineAligned(Z)V

    :cond_2
    sget p2, La/b/j;->LinearLayoutCompat_android_weightSum:I

    const/high16 p3, -0x40800000    # -1.0f

    .line 9
    invoke-virtual {v3, p2, p3}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result p2

    .line 10
    iput p2, p0, La/b/p/i0;->h:F

    sget p2, La/b/j;->LinearLayoutCompat_android_baselineAlignedChildIndex:I

    .line 11
    invoke-virtual {v3, p2, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result p2

    .line 12
    iput p2, p0, La/b/p/i0;->c:I

    sget p2, La/b/j;->LinearLayoutCompat_measureWithLargestChild:I

    .line 13
    invoke-virtual {v3, p2, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result p2

    .line 14
    iput-boolean p2, p0, La/b/p/i0;->i:Z

    sget p2, La/b/j;->LinearLayoutCompat_divider:I

    .line 15
    invoke-virtual {v3, p2}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result p3

    if-eqz p3, :cond_3

    invoke-virtual {v3, p2, v2}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result p3

    if-eqz p3, :cond_3

    invoke-static {p1, p3}, La/b/l/a/a;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    goto :goto_0

    :cond_3
    invoke-virtual {v3, p2}, Landroid/content/res/TypedArray;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    move-result-object p1

    .line 16
    :goto_0
    invoke-virtual {p0, p1}, La/b/p/i0;->setDividerDrawable(Landroid/graphics/drawable/Drawable;)V

    sget p1, La/b/j;->LinearLayoutCompat_showDividers:I

    .line 17
    invoke-virtual {v3, p1, v2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result p1

    .line 18
    iput p1, p0, La/b/p/i0;->o:I

    sget p1, La/b/j;->LinearLayoutCompat_dividerPadding:I

    .line 19
    invoke-virtual {v3, p1, v2}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result p1

    .line 20
    iput p1, p0, La/b/p/i0;->p:I

    .line 21
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    return-void
.end method


# virtual methods
.method public checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z
    .locals 0

    instance-of p1, p1, La/b/p/i0$a;

    return p1
.end method

.method public e(Landroid/graphics/Canvas;I)V
    .locals 4

    iget-object v0, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v1

    iget v2, p0, La/b/p/i0;->p:I

    add-int/2addr v1, v2

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getWidth()I

    move-result v2

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v3

    sub-int/2addr v2, v3

    iget v3, p0, La/b/p/i0;->p:I

    sub-int/2addr v2, v3

    iget v3, p0, La/b/p/i0;->n:I

    add-int/2addr v3, p2

    invoke-virtual {v0, v1, p2, v2, v3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    iget-object p2, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    return-void
.end method

.method public f(Landroid/graphics/Canvas;I)V
    .locals 5

    iget-object v0, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v1

    iget v2, p0, La/b/p/i0;->p:I

    add-int/2addr v1, v2

    iget v2, p0, La/b/p/i0;->m:I

    add-int/2addr v2, p2

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getHeight()I

    move-result v3

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v4

    sub-int/2addr v3, v4

    iget v4, p0, La/b/p/i0;->p:I

    sub-int/2addr v3, v4

    invoke-virtual {v0, p2, v1, v2, v3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    iget-object p2, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    invoke-virtual {p2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    return-void
.end method

.method public g()La/b/p/i0$a;
    .locals 3

    iget v0, p0, La/b/p/i0;->e:I

    const/4 v1, -0x2

    if-nez v0, :cond_0

    new-instance v0, La/b/p/i0$a;

    invoke-direct {v0, v1, v1}, La/b/p/i0$a;-><init>(II)V

    return-object v0

    :cond_0
    const/4 v2, 0x1

    if-ne v0, v2, :cond_1

    new-instance v0, La/b/p/i0$a;

    const/4 v2, -0x1

    invoke-direct {v0, v2, v1}, La/b/p/i0$a;-><init>(II)V

    return-object v0

    :cond_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public bridge synthetic generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 1

    invoke-virtual {p0}, La/b/p/i0;->g()La/b/p/i0$a;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    invoke-virtual {p0, p1}, La/b/p/i0;->h(Landroid/util/AttributeSet;)La/b/p/i0$a;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    invoke-virtual {p0, p1}, La/b/p/i0;->i(Landroid/view/ViewGroup$LayoutParams;)La/b/p/i0$a;

    move-result-object p1

    return-object p1
.end method

.method public getBaseline()I
    .locals 5

    iget v0, p0, La/b/p/i0;->c:I

    if-gez v0, :cond_0

    invoke-super {p0}, Landroid/view/ViewGroup;->getBaseline()I

    move-result v0

    return v0

    :cond_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    iget v1, p0, La/b/p/i0;->c:I

    if-le v0, v1, :cond_6

    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getBaseline()I

    move-result v1

    const/4 v2, -0x1

    if-ne v1, v2, :cond_2

    iget v0, p0, La/b/p/i0;->c:I

    if-nez v0, :cond_1

    return v2

    :cond_1
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "mBaselineAlignedChildIndex of LinearLayout points to a View that doesn\'t know how to get its baseline."

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    iget v2, p0, La/b/p/i0;->d:I

    iget v3, p0, La/b/p/i0;->e:I

    const/4 v4, 0x1

    if-ne v3, v4, :cond_5

    iget v3, p0, La/b/p/i0;->f:I

    and-int/lit8 v3, v3, 0x70

    const/16 v4, 0x30

    if-eq v3, v4, :cond_5

    const/16 v4, 0x10

    if-eq v3, v4, :cond_4

    const/16 v4, 0x50

    if-eq v3, v4, :cond_3

    goto :goto_0

    :cond_3
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getBottom()I

    move-result v2

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getTop()I

    move-result v3

    sub-int/2addr v2, v3

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v3

    sub-int/2addr v2, v3

    iget v3, p0, La/b/p/i0;->g:I

    sub-int/2addr v2, v3

    goto :goto_0

    :cond_4
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getBottom()I

    move-result v3

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getTop()I

    move-result v4

    sub-int/2addr v3, v4

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v4

    sub-int/2addr v3, v4

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v4

    sub-int/2addr v3, v4

    iget v4, p0, La/b/p/i0;->g:I

    sub-int/2addr v3, v4

    div-int/lit8 v3, v3, 0x2

    add-int/2addr v2, v3

    :cond_5
    :goto_0
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, La/b/p/i0$a;

    iget v0, v0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v2, v0

    add-int/2addr v2, v1

    return v2

    :cond_6
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "mBaselineAlignedChildIndex of LinearLayout set to an index that is out of bounds."

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public getBaselineAlignedChildIndex()I
    .locals 1

    iget v0, p0, La/b/p/i0;->c:I

    return v0
.end method

.method public getDividerDrawable()Landroid/graphics/drawable/Drawable;
    .locals 1

    iget-object v0, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    return-object v0
.end method

.method public getDividerPadding()I
    .locals 1

    iget v0, p0, La/b/p/i0;->p:I

    return v0
.end method

.method public getDividerWidth()I
    .locals 1

    iget v0, p0, La/b/p/i0;->m:I

    return v0
.end method

.method public getGravity()I
    .locals 1

    iget v0, p0, La/b/p/i0;->f:I

    return v0
.end method

.method public getOrientation()I
    .locals 1

    iget v0, p0, La/b/p/i0;->e:I

    return v0
.end method

.method public getShowDividers()I
    .locals 1

    iget v0, p0, La/b/p/i0;->o:I

    return v0
.end method

.method public getVirtualChildCount()I
    .locals 1

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    return v0
.end method

.method public getWeightSum()F
    .locals 1

    iget v0, p0, La/b/p/i0;->h:F

    return v0
.end method

.method public h(Landroid/util/AttributeSet;)La/b/p/i0$a;
    .locals 2

    new-instance v0, La/b/p/i0$a;

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1, p1}, La/b/p/i0$a;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-object v0
.end method

.method public i(Landroid/view/ViewGroup$LayoutParams;)La/b/p/i0$a;
    .locals 1

    new-instance v0, La/b/p/i0$a;

    invoke-direct {v0, p1}, La/b/p/i0$a;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    return-object v0
.end method

.method public j()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public k()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public l()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public m(I)Z
    .locals 4

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-nez p1, :cond_1

    iget p1, p0, La/b/p/i0;->o:I

    and-int/2addr p1, v1

    if-eqz p1, :cond_0

    move v0, v1

    :cond_0
    return v0

    :cond_1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v2

    if-ne p1, v2, :cond_3

    iget p1, p0, La/b/p/i0;->o:I

    and-int/lit8 p1, p1, 0x4

    if-eqz p1, :cond_2

    move v0, v1

    :cond_2
    return v0

    :cond_3
    iget v2, p0, La/b/p/i0;->o:I

    and-int/lit8 v2, v2, 0x2

    if-eqz v2, :cond_5

    sub-int/2addr p1, v1

    :goto_0
    if-ltz p1, :cond_5

    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v2

    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    move-result v2

    const/16 v3, 0x8

    if-eq v2, v3, :cond_4

    move v0, v1

    goto :goto_1

    :cond_4
    add-int/lit8 p1, p1, -0x1

    goto :goto_0

    :cond_5
    :goto_1
    return v0
.end method

.method public n(Landroid/view/View;IIII)V
    .locals 0

    invoke-virtual/range {p0 .. p5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    return-void
.end method

.method public o()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public onDraw(Landroid/graphics/Canvas;)V
    .locals 6

    iget-object v0, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget v0, p0, La/b/p/i0;->e:I

    const/16 v1, 0x8

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ne v0, v3, :cond_4

    .line 1
    invoke-virtual {p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v0

    :goto_0
    if-ge v2, v0, :cond_2

    .line 2
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    if-eqz v3, :cond_1

    .line 3
    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    move-result v4

    if-eq v4, v1, :cond_1

    invoke-virtual {p0, v2}, La/b/p/i0;->m(I)Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v4

    check-cast v4, La/b/p/i0$a;

    invoke-virtual {v3}, Landroid/view/View;->getTop()I

    move-result v3

    iget v4, v4, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    sub-int/2addr v3, v4

    iget v4, p0, La/b/p/i0;->n:I

    sub-int/2addr v3, v4

    invoke-virtual {p0, p1, v3}, La/b/p/i0;->e(Landroid/graphics/Canvas;I)V

    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    invoke-virtual {p0, v0}, La/b/p/i0;->m(I)Z

    move-result v1

    if-eqz v1, :cond_b

    add-int/lit8 v0, v0, -0x1

    .line 4
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    if-nez v0, :cond_3

    .line 5
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getHeight()I

    move-result v0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v1

    sub-int/2addr v0, v1

    iget v1, p0, La/b/p/i0;->n:I

    sub-int/2addr v0, v1

    goto :goto_1

    :cond_3
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v1

    check-cast v1, La/b/p/i0$a;

    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    move-result v0

    iget v1, v1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v0, v1

    :goto_1
    invoke-virtual {p0, p1, v0}, La/b/p/i0;->e(Landroid/graphics/Canvas;I)V

    goto/16 :goto_6

    .line 6
    :cond_4
    invoke-virtual {p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v0

    invoke-static {p0}, La/b/p/d1;->b(Landroid/view/View;)Z

    move-result v3

    :goto_2
    if-ge v2, v0, :cond_7

    .line 7
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v4

    if-eqz v4, :cond_6

    .line 8
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    move-result v5

    if-eq v5, v1, :cond_6

    invoke-virtual {p0, v2}, La/b/p/i0;->m(I)Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v5

    check-cast v5, La/b/p/i0$a;

    if-eqz v3, :cond_5

    invoke-virtual {v4}, Landroid/view/View;->getRight()I

    move-result v4

    iget v5, v5, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v4, v5

    goto :goto_3

    :cond_5
    invoke-virtual {v4}, Landroid/view/View;->getLeft()I

    move-result v4

    iget v5, v5, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    sub-int/2addr v4, v5

    iget v5, p0, La/b/p/i0;->m:I

    sub-int/2addr v4, v5

    :goto_3
    invoke-virtual {p0, p1, v4}, La/b/p/i0;->f(Landroid/graphics/Canvas;I)V

    :cond_6
    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_7
    invoke-virtual {p0, v0}, La/b/p/i0;->m(I)Z

    move-result v1

    if-eqz v1, :cond_b

    add-int/lit8 v0, v0, -0x1

    .line 9
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    if-nez v0, :cond_9

    if-eqz v3, :cond_8

    .line 10
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v0

    goto :goto_5

    :cond_8
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getWidth()I

    move-result v0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v1

    goto :goto_4

    :cond_9
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v1

    check-cast v1, La/b/p/i0$a;

    if-eqz v3, :cond_a

    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    move-result v0

    iget v1, v1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    :goto_4
    sub-int/2addr v0, v1

    iget v1, p0, La/b/p/i0;->m:I

    sub-int/2addr v0, v1

    goto :goto_5

    :cond_a
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    move-result v0

    iget v1, v1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v0, v1

    :goto_5
    invoke-virtual {p0, p1, v0}, La/b/p/i0;->f(Landroid/graphics/Canvas;I)V

    :cond_b
    :goto_6
    return-void
.end method

.method public onInitializeAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 1

    invoke-super {p0, p1}, Landroid/view/ViewGroup;->onInitializeAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V

    const-string v0, "androidx.appcompat.widget.LinearLayoutCompat"

    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityEvent;->setClassName(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public onInitializeAccessibilityNodeInfo(Landroid/view/accessibility/AccessibilityNodeInfo;)V
    .locals 1

    invoke-super {p0, p1}, Landroid/view/ViewGroup;->onInitializeAccessibilityNodeInfo(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    const-string v0, "androidx.appcompat.widget.LinearLayoutCompat"

    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setClassName(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public onLayout(ZIIII)V
    .locals 23

    move-object/from16 v0, p0

    iget v1, v0, La/b/p/i0;->e:I

    const/16 v2, 0x50

    const/16 v3, 0x10

    const/16 v4, 0x8

    const/4 v6, 0x5

    const v7, 0x800007

    const/4 v8, 0x2

    const/4 v9, 0x1

    if-ne v1, v9, :cond_8

    .line 1
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v1

    sub-int v10, p4, p2

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v11

    sub-int v11, v10, v11

    sub-int/2addr v10, v1

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v12

    sub-int/2addr v10, v12

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v12

    iget v13, v0, La/b/p/i0;->f:I

    and-int/lit8 v14, v13, 0x70

    and-int/2addr v7, v13

    if-eq v14, v3, :cond_1

    if-eq v14, v2, :cond_0

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v2

    goto :goto_0

    :cond_0
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v2

    add-int v2, v2, p5

    sub-int v2, v2, p3

    iget v3, v0, La/b/p/i0;->g:I

    sub-int/2addr v2, v3

    goto :goto_0

    :cond_1
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v2

    sub-int v3, p5, p3

    iget v13, v0, La/b/p/i0;->g:I

    sub-int/2addr v3, v13

    div-int/2addr v3, v8

    add-int/2addr v2, v3

    :goto_0
    const/4 v5, 0x0

    :goto_1
    if-ge v5, v12, :cond_16

    .line 2
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    if-nez v3, :cond_2

    .line 3
    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v3

    add-int/2addr v3, v2

    goto :goto_4

    :cond_2
    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    move-result v13

    if-eq v13, v4, :cond_7

    invoke-virtual {v3}, Landroid/view/View;->getMeasuredWidth()I

    move-result v13

    invoke-virtual {v3}, Landroid/view/View;->getMeasuredHeight()I

    move-result v14

    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v15

    check-cast v15, La/b/p/i0$a;

    iget v4, v15, La/b/p/i0$a;->b:I

    if-gez v4, :cond_3

    move v4, v7

    :cond_3
    invoke-static/range {p0 .. p0}, La/f/j/k;->f(Landroid/view/View;)I

    move-result v8

    .line 4
    invoke-static {v4, v8}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    move-result v4

    and-int/lit8 v4, v4, 0x7

    if-eq v4, v9, :cond_5

    if-eq v4, v6, :cond_4

    .line 5
    iget v4, v15, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v4, v1

    goto :goto_3

    :cond_4
    sub-int v4, v11, v13

    goto :goto_2

    :cond_5
    sub-int v4, v10, v13

    const/4 v8, 0x2

    div-int/2addr v4, v8

    add-int/2addr v4, v1

    iget v8, v15, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v4, v8

    :goto_2
    iget v8, v15, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    sub-int/2addr v4, v8

    :goto_3
    invoke-virtual {v0, v5}, La/b/p/i0;->m(I)Z

    move-result v8

    if-eqz v8, :cond_6

    iget v8, v0, La/b/p/i0;->n:I

    add-int/2addr v2, v8

    :cond_6
    iget v8, v15, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v2, v8

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->k()I

    move-result v8

    add-int/2addr v8, v2

    add-int/2addr v13, v4

    add-int v6, v14, v8

    .line 6
    invoke-virtual {v3, v4, v8, v13, v6}, Landroid/view/View;->layout(IIII)V

    .line 7
    iget v3, v15, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v14, v3

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v3

    add-int/2addr v3, v14

    add-int/2addr v3, v2

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v2

    add-int/2addr v2, v5

    move v5, v2

    :goto_4
    move v2, v3

    :cond_7
    add-int/2addr v5, v9

    const/16 v4, 0x8

    const/4 v6, 0x5

    const/4 v8, 0x2

    goto :goto_1

    .line 8
    :cond_8
    invoke-static/range {p0 .. p0}, La/b/p/d1;->b(Landroid/view/View;)Z

    move-result v1

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v4

    sub-int v6, p5, p3

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v8

    sub-int v8, v6, v8

    sub-int/2addr v6, v4

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v10

    sub-int/2addr v6, v10

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v10

    iget v11, v0, La/b/p/i0;->f:I

    and-int/2addr v7, v11

    and-int/lit8 v11, v11, 0x70

    iget-boolean v12, v0, La/b/p/i0;->b:Z

    iget-object v13, v0, La/b/p/i0;->j:[I

    iget-object v14, v0, La/b/p/i0;->k:[I

    .line 9
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->getLayoutDirection()I

    move-result v15

    .line 10
    invoke-static {v7, v15}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    move-result v7

    if-eq v7, v9, :cond_a

    const/4 v15, 0x5

    if-eq v7, v15, :cond_9

    .line 11
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v7

    goto :goto_5

    :cond_9
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v7

    add-int v7, v7, p4

    sub-int v7, v7, p2

    iget v15, v0, La/b/p/i0;->g:I

    sub-int/2addr v7, v15

    goto :goto_5

    :cond_a
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v7

    sub-int v15, p4, p2

    iget v5, v0, La/b/p/i0;->g:I

    sub-int/2addr v15, v5

    const/4 v5, 0x2

    div-int/2addr v15, v5

    add-int/2addr v7, v15

    :goto_5
    if-eqz v1, :cond_b

    add-int/lit8 v1, v10, -0x1

    move/from16 v16, v1

    const/4 v1, 0x0

    const/4 v15, -0x1

    goto :goto_6

    :cond_b
    move v15, v9

    const/4 v1, 0x0

    const/16 v16, 0x0

    :goto_6
    if-ge v1, v10, :cond_16

    mul-int v17, v15, v1

    add-int v9, v17, v16

    .line 12
    invoke-virtual {v0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v2

    if-nez v2, :cond_d

    .line 13
    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v2

    add-int/2addr v2, v7

    move v7, v2

    :cond_c
    move/from16 p3, v10

    move/from16 p5, v11

    move/from16 v20, v12

    :goto_7
    const/4 v2, 0x1

    goto/16 :goto_a

    :cond_d
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    move-result v3

    const/16 v5, 0x8

    if-eq v3, v5, :cond_c

    invoke-virtual {v2}, Landroid/view/View;->getMeasuredWidth()I

    move-result v3

    invoke-virtual {v2}, Landroid/view/View;->getMeasuredHeight()I

    move-result v19

    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v20

    move-object/from16 v5, v20

    check-cast v5, La/b/p/i0$a;

    move/from16 p3, v10

    if-eqz v12, :cond_e

    iget v10, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    move/from16 p5, v11

    const/4 v11, -0x1

    if-eq v10, v11, :cond_f

    invoke-virtual {v2}, Landroid/view/View;->getBaseline()I

    move-result v11

    goto :goto_8

    :cond_e
    move/from16 p5, v11

    :cond_f
    const/4 v11, -0x1

    :goto_8
    iget v10, v5, La/b/p/i0$a;->b:I

    if-gez v10, :cond_10

    move/from16 v10, p5

    :cond_10
    and-int/lit8 v10, v10, 0x70

    move/from16 v20, v12

    const/16 v12, 0x10

    if-eq v10, v12, :cond_13

    const/16 v12, 0x30

    if-eq v10, v12, :cond_12

    const/16 v12, 0x50

    if-eq v10, v12, :cond_11

    move v10, v4

    const/4 v12, -0x1

    goto :goto_9

    :cond_11
    sub-int v10, v8, v19

    iget v12, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    sub-int/2addr v10, v12

    const/4 v12, -0x1

    if-eq v11, v12, :cond_14

    invoke-virtual {v2}, Landroid/view/View;->getMeasuredHeight()I

    move-result v21

    sub-int v21, v21, v11

    const/4 v11, 0x2

    aget v22, v14, v11

    sub-int v22, v22, v21

    sub-int v10, v10, v22

    goto :goto_9

    :cond_12
    const/4 v12, -0x1

    iget v10, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v10, v4

    if-eq v11, v12, :cond_14

    const/16 v18, 0x1

    aget v21, v13, v18

    sub-int v21, v21, v11

    add-int v10, v21, v10

    goto :goto_9

    :cond_13
    const/4 v12, -0x1

    sub-int v10, v6, v19

    const/4 v11, 0x2

    div-int/2addr v10, v11

    add-int/2addr v10, v4

    iget v11, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v10, v11

    iget v11, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    sub-int/2addr v10, v11

    :cond_14
    :goto_9
    invoke-virtual {v0, v9}, La/b/p/i0;->m(I)Z

    move-result v9

    if-eqz v9, :cond_15

    iget v9, v0, La/b/p/i0;->m:I

    add-int/2addr v7, v9

    :cond_15
    iget v9, v5, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v7, v9

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->k()I

    move-result v9

    add-int/2addr v9, v7

    add-int v11, v3, v9

    add-int v12, v19, v10

    .line 14
    invoke-virtual {v2, v9, v10, v11, v12}, Landroid/view/View;->layout(IIII)V

    .line 15
    iget v2, v5, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v3, v2

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v2

    add-int/2addr v2, v3

    add-int/2addr v7, v2

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v2

    add-int/2addr v2, v1

    move v1, v2

    goto/16 :goto_7

    :goto_a
    add-int/2addr v1, v2

    move/from16 v10, p3

    move/from16 v11, p5

    move v9, v2

    move/from16 v12, v20

    const/16 v2, 0x50

    const/16 v3, 0x10

    goto/16 :goto_6

    :cond_16
    return-void
.end method

.method public onMeasure(II)V
    .locals 38

    move-object/from16 v6, p0

    move/from16 v7, p1

    move/from16 v8, p2

    iget v0, v6, La/b/p/i0;->e:I

    const/4 v10, -0x2

    const/high16 v11, -0x80000000

    const/16 v12, 0x8

    const/4 v13, 0x0

    const/high16 v15, 0x40000000    # 2.0f

    const/4 v5, 0x1

    const/4 v4, 0x0

    if-ne v0, v5, :cond_29

    .line 1
    iput v4, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v3

    invoke-static/range {p1 .. p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result v2

    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result v1

    iget v0, v6, La/b/p/i0;->c:I

    iget-boolean v9, v6, La/b/p/i0;->i:Z

    move v14, v4

    move/from16 v17, v14

    move/from16 v18, v17

    move/from16 v19, v18

    move/from16 v20, v19

    move/from16 v22, v20

    move/from16 v24, v22

    move/from16 v25, v24

    move/from16 v23, v5

    move/from16 v21, v13

    :goto_0
    if-ge v14, v3, :cond_10

    .line 2
    invoke-virtual {v6, v14}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v26

    if-nez v26, :cond_0

    .line 3
    iget v4, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v26

    add-int v4, v26, v4

    iput v4, v6, La/b/p/i0;->g:I

    goto :goto_1

    :cond_0
    invoke-virtual/range {v26 .. v26}, Landroid/view/View;->getVisibility()I

    move-result v4

    if-ne v4, v12, :cond_1

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v4

    add-int/2addr v14, v4

    :goto_1
    move v10, v0

    move/from16 v29, v1

    move v0, v2

    move/from16 v31, v3

    move/from16 v27, v5

    move/from16 v4, v20

    goto/16 :goto_b

    :cond_1
    invoke-virtual {v6, v14}, La/b/p/i0;->m(I)Z

    move-result v4

    if-eqz v4, :cond_2

    iget v4, v6, La/b/p/i0;->g:I

    iget v5, v6, La/b/p/i0;->n:I

    add-int/2addr v4, v5

    iput v4, v6, La/b/p/i0;->g:I

    :cond_2
    invoke-virtual/range {v26 .. v26}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v4

    move-object v5, v4

    check-cast v5, La/b/p/i0$a;

    iget v4, v5, La/b/p/i0$a;->a:F

    add-float v21, v21, v4

    if-ne v1, v15, :cond_3

    iget v12, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    if-nez v12, :cond_3

    cmpl-float v4, v4, v13

    if-lez v4, :cond_3

    iget v4, v6, La/b/p/i0;->g:I

    iget v12, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v12, v4

    iget v15, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v12, v15

    invoke-static {v4, v12}, Ljava/lang/Math;->max(II)I

    move-result v4

    iput v4, v6, La/b/p/i0;->g:I

    move v10, v0

    move/from16 v29, v1

    move/from16 v30, v2

    move/from16 v31, v3

    move-object v13, v5

    const/4 v5, 0x1

    const/16 v27, 0x1

    goto :goto_4

    :cond_3
    iget v4, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    if-nez v4, :cond_4

    iget v4, v5, La/b/p/i0$a;->a:F

    cmpl-float v4, v4, v13

    if-lez v4, :cond_4

    iput v10, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v12, 0x0

    goto :goto_2

    :cond_4
    move v12, v11

    :goto_2
    const/4 v4, 0x0

    cmpl-float v15, v21, v13

    if-nez v15, :cond_5

    iget v15, v6, La/b/p/i0;->g:I

    move v10, v0

    goto :goto_3

    :cond_5
    move v10, v0

    const/4 v15, 0x0

    :goto_3
    move-object/from16 v0, p0

    move/from16 v29, v1

    move-object/from16 v1, v26

    move/from16 v30, v2

    move/from16 v2, p1

    move/from16 v31, v3

    move v3, v4

    move/from16 v4, p2

    move-object v13, v5

    const/16 v27, 0x1

    move v5, v15

    invoke-virtual/range {v0 .. v5}, La/b/p/i0;->n(Landroid/view/View;IIII)V

    if-eq v12, v11, :cond_6

    iput v12, v13, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    :cond_6
    invoke-virtual/range {v26 .. v26}, Landroid/view/View;->getMeasuredHeight()I

    move-result v0

    iget v1, v6, La/b/p/i0;->g:I

    add-int v2, v1, v0

    iget v3, v13, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v2, v3

    iget v3, v13, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v2, v3

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v3

    add-int/2addr v3, v2

    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    move-result v1

    iput v1, v6, La/b/p/i0;->g:I

    move/from16 v4, v18

    if-eqz v9, :cond_7

    invoke-static {v0, v4}, Ljava/lang/Math;->max(II)I

    move-result v18

    :cond_7
    move/from16 v5, v22

    :goto_4
    if-ltz v10, :cond_8

    add-int/lit8 v0, v14, 0x1

    if-ne v10, v0, :cond_8

    iget v0, v6, La/b/p/i0;->g:I

    iput v0, v6, La/b/p/i0;->d:I

    :cond_8
    if-ge v14, v10, :cond_a

    iget v0, v13, La/b/p/i0$a;->a:F

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-gtz v0, :cond_9

    goto :goto_5

    :cond_9
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "A child of LinearLayout with index less than mBaselineAlignedChildIndex has weight > 0, which won\'t work.  Either remove the weight, or don\'t set mBaselineAlignedChildIndex."

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a
    :goto_5
    move/from16 v0, v30

    const/high16 v1, 0x40000000    # 2.0f

    if-eq v0, v1, :cond_b

    iget v1, v13, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    const/4 v2, -0x1

    if-ne v1, v2, :cond_b

    move/from16 v1, v27

    move/from16 v24, v1

    goto :goto_6

    :cond_b
    const/4 v1, 0x0

    :goto_6
    iget v2, v13, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iget v3, v13, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v2, v3

    invoke-virtual/range {v26 .. v26}, Landroid/view/View;->getMeasuredWidth()I

    move-result v3

    add-int/2addr v3, v2

    move/from16 v12, v20

    invoke-static {v12, v3}, Ljava/lang/Math;->max(II)I

    move-result v4

    invoke-virtual/range {v26 .. v26}, Landroid/view/View;->getMeasuredState()I

    move-result v12

    move/from16 v15, v25

    invoke-static {v15, v12}, Landroid/view/View;->combineMeasuredStates(II)I

    move-result v12

    if-eqz v23, :cond_c

    iget v15, v13, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    const/4 v11, -0x1

    if-ne v15, v11, :cond_c

    move/from16 v11, v27

    goto :goto_7

    :cond_c
    const/4 v11, 0x0

    :goto_7
    iget v13, v13, La/b/p/i0$a;->a:F

    const/4 v15, 0x0

    cmpl-float v13, v13, v15

    if-lez v13, :cond_e

    if-eqz v1, :cond_d

    goto :goto_8

    :cond_d
    move v2, v3

    :goto_8
    move/from16 v13, v17

    invoke-static {v13, v2}, Ljava/lang/Math;->max(II)I

    move-result v17

    goto :goto_a

    :cond_e
    move/from16 v13, v17

    if-eqz v1, :cond_f

    goto :goto_9

    :cond_f
    move v2, v3

    :goto_9
    move/from16 v1, v19

    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    move-result v19

    move/from16 v17, v13

    :goto_a
    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v1

    add-int/2addr v14, v1

    move/from16 v22, v5

    move/from16 v23, v11

    move/from16 v25, v12

    :goto_b
    add-int/lit8 v14, v14, 0x1

    move v2, v0

    move/from16 v20, v4

    move v0, v10

    move/from16 v5, v27

    move/from16 v1, v29

    move/from16 v3, v31

    const/4 v4, 0x0

    const/4 v10, -0x2

    const/high16 v11, -0x80000000

    const/16 v12, 0x8

    const/4 v13, 0x0

    const/high16 v15, 0x40000000    # 2.0f

    goto/16 :goto_0

    :cond_10
    move/from16 v29, v1

    move v0, v2

    move/from16 v31, v3

    move/from16 v27, v5

    move/from16 v13, v17

    move/from16 v4, v18

    move/from16 v1, v19

    move/from16 v12, v20

    move/from16 v15, v25

    iget v2, v6, La/b/p/i0;->g:I

    move/from16 v10, v31

    if-lez v2, :cond_11

    invoke-virtual {v6, v10}, La/b/p/i0;->m(I)Z

    move-result v2

    if-eqz v2, :cond_11

    iget v2, v6, La/b/p/i0;->g:I

    iget v3, v6, La/b/p/i0;->n:I

    add-int/2addr v2, v3

    iput v2, v6, La/b/p/i0;->g:I

    :cond_11
    move/from16 v2, v29

    if-eqz v9, :cond_15

    const/high16 v3, -0x80000000

    if-eq v2, v3, :cond_12

    if-nez v2, :cond_15

    :cond_12
    const/4 v11, 0x0

    iput v11, v6, La/b/p/i0;->g:I

    move v3, v11

    :goto_c
    if-ge v3, v10, :cond_15

    .line 4
    invoke-virtual {v6, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v5

    if-nez v5, :cond_13

    .line 5
    iget v5, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v14

    add-int/2addr v14, v5

    iput v14, v6, La/b/p/i0;->g:I

    goto :goto_d

    :cond_13
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    move-result v14

    const/16 v11, 0x8

    if-ne v14, v11, :cond_14

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v5

    add-int/2addr v3, v5

    goto :goto_d

    :cond_14
    invoke-virtual {v5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v5

    check-cast v5, La/b/p/i0$a;

    iget v11, v6, La/b/p/i0;->g:I

    add-int v18, v11, v4

    iget v14, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int v18, v18, v14

    iget v5, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int v18, v18, v5

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v5

    add-int v5, v5, v18

    invoke-static {v11, v5}, Ljava/lang/Math;->max(II)I

    move-result v5

    iput v5, v6, La/b/p/i0;->g:I

    :goto_d
    add-int/lit8 v3, v3, 0x1

    const/4 v11, 0x0

    goto :goto_c

    :cond_15
    iget v3, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v5

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v11

    add-int/2addr v11, v5

    add-int/2addr v11, v3

    iput v11, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getSuggestedMinimumHeight()I

    move-result v3

    invoke-static {v11, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    const/4 v5, 0x0

    invoke-static {v3, v8, v5}, Landroid/view/View;->resolveSizeAndState(III)I

    move-result v3

    const v5, 0xffffff

    and-int/2addr v5, v3

    iget v11, v6, La/b/p/i0;->g:I

    sub-int/2addr v5, v11

    if-nez v22, :cond_1a

    if-eqz v5, :cond_16

    const/4 v11, 0x0

    cmpl-float v14, v21, v11

    if-lez v14, :cond_16

    goto :goto_11

    :cond_16
    invoke-static {v1, v13}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-eqz v9, :cond_19

    const/high16 v5, 0x40000000    # 2.0f

    if-eq v2, v5, :cond_19

    const/4 v2, 0x0

    :goto_e
    if-ge v2, v10, :cond_19

    .line 6
    invoke-virtual {v6, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v5

    if-eqz v5, :cond_18

    .line 7
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    move-result v9

    const/16 v11, 0x8

    if-ne v9, v11, :cond_17

    goto :goto_f

    :cond_17
    invoke-virtual {v5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v9

    check-cast v9, La/b/p/i0$a;

    iget v9, v9, La/b/p/i0$a;->a:F

    const/4 v11, 0x0

    cmpl-float v9, v9, v11

    if-lez v9, :cond_18

    invoke-virtual {v5}, Landroid/view/View;->getMeasuredWidth()I

    move-result v9

    const/high16 v11, 0x40000000    # 2.0f

    invoke-static {v9, v11}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v9

    invoke-static {v4, v11}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v13

    invoke-virtual {v5, v9, v13}, Landroid/view/View;->measure(II)V

    :cond_18
    :goto_f
    add-int/lit8 v2, v2, 0x1

    goto :goto_e

    :cond_19
    :goto_10
    move/from16 v20, v12

    goto/16 :goto_19

    :cond_1a
    :goto_11
    iget v4, v6, La/b/p/i0;->h:F

    const/4 v9, 0x0

    cmpl-float v11, v4, v9

    if-lez v11, :cond_1b

    move/from16 v21, v4

    :cond_1b
    const/4 v4, 0x0

    iput v4, v6, La/b/p/i0;->g:I

    const/4 v4, 0x0

    :goto_12
    if-ge v4, v10, :cond_26

    .line 8
    invoke-virtual {v6, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v9

    .line 9
    invoke-virtual {v9}, Landroid/view/View;->getVisibility()I

    move-result v11

    const/16 v13, 0x8

    if-ne v11, v13, :cond_1c

    move/from16 v29, v2

    goto/16 :goto_18

    :cond_1c
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v11

    check-cast v11, La/b/p/i0$a;

    iget v13, v11, La/b/p/i0$a;->a:F

    const/4 v14, 0x0

    cmpl-float v16, v13, v14

    if-lez v16, :cond_21

    int-to-float v14, v5

    mul-float/2addr v14, v13

    div-float v14, v14, v21

    float-to-int v14, v14

    sub-float v21, v21, v13

    sub-int/2addr v5, v14

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v13

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v16

    add-int v16, v16, v13

    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int v16, v16, v13

    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int v13, v16, v13

    move/from16 v16, v5

    iget v5, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    invoke-static {v7, v13, v5}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v5

    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    if-nez v13, :cond_1e

    const/high16 v13, 0x40000000    # 2.0f

    if-eq v2, v13, :cond_1d

    goto :goto_13

    :cond_1d
    if-lez v14, :cond_1f

    move v13, v14

    goto :goto_14

    :cond_1e
    :goto_13
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredHeight()I

    move-result v13

    add-int/2addr v13, v14

    if-gez v13, :cond_20

    :cond_1f
    const/4 v13, 0x0

    :cond_20
    :goto_14
    const/high16 v14, 0x40000000    # 2.0f

    invoke-static {v13, v14}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v13

    invoke-virtual {v9, v5, v13}, Landroid/view/View;->measure(II)V

    invoke-virtual {v9}, Landroid/view/View;->getMeasuredState()I

    move-result v5

    and-int/lit16 v5, v5, -0x100

    invoke-static {v15, v5}, Landroid/view/View;->combineMeasuredStates(II)I

    move-result v15

    move/from16 v5, v16

    :cond_21
    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iget v14, v11, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v13, v14

    invoke-virtual {v9}, Landroid/view/View;->getMeasuredWidth()I

    move-result v14

    add-int/2addr v14, v13

    invoke-static {v12, v14}, Ljava/lang/Math;->max(II)I

    move-result v12

    move/from16 v29, v2

    const/high16 v2, 0x40000000    # 2.0f

    if-eq v0, v2, :cond_22

    iget v2, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    move/from16 v16, v5

    const/4 v5, -0x1

    if-ne v2, v5, :cond_23

    move/from16 v2, v27

    goto :goto_15

    :cond_22
    move/from16 v16, v5

    const/4 v5, -0x1

    :cond_23
    const/4 v2, 0x0

    :goto_15
    if-eqz v2, :cond_24

    goto :goto_16

    :cond_24
    move v13, v14

    :goto_16
    invoke-static {v1, v13}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-eqz v23, :cond_25

    iget v2, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    if-ne v2, v5, :cond_25

    move/from16 v5, v27

    goto :goto_17

    :cond_25
    const/4 v5, 0x0

    :goto_17
    iget v2, v6, La/b/p/i0;->g:I

    invoke-virtual {v9}, Landroid/view/View;->getMeasuredHeight()I

    move-result v9

    add-int/2addr v9, v2

    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int/2addr v9, v13

    iget v11, v11, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v9, v11

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v11

    add-int/2addr v11, v9

    invoke-static {v2, v11}, Ljava/lang/Math;->max(II)I

    move-result v2

    iput v2, v6, La/b/p/i0;->g:I

    move/from16 v23, v5

    move/from16 v5, v16

    :goto_18
    add-int/lit8 v4, v4, 0x1

    move/from16 v2, v29

    goto/16 :goto_12

    :cond_26
    iget v2, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v4

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v5

    add-int/2addr v5, v4

    add-int/2addr v5, v2

    iput v5, v6, La/b/p/i0;->g:I

    goto/16 :goto_10

    :goto_19
    if-nez v23, :cond_27

    const/high16 v2, 0x40000000    # 2.0f

    if-eq v0, v2, :cond_27

    goto :goto_1a

    :cond_27
    move/from16 v1, v20

    :goto_1a
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v0

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v2

    add-int/2addr v2, v0

    add-int/2addr v2, v1

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getSuggestedMinimumWidth()I

    move-result v0

    invoke-static {v2, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-static {v0, v7, v15}, Landroid/view/View;->resolveSizeAndState(III)I

    move-result v0

    invoke-virtual {v6, v0, v3}, Landroid/view/ViewGroup;->setMeasuredDimension(II)V

    if-eqz v24, :cond_63

    .line 10
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getMeasuredWidth()I

    move-result v0

    const/high16 v1, 0x40000000    # 2.0f

    invoke-static {v0, v1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v7

    const/4 v9, 0x0

    :goto_1b
    if-ge v9, v10, :cond_63

    .line 11
    invoke-virtual {v6, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    .line 12
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    move-result v0

    const/16 v2, 0x8

    if-eq v0, v2, :cond_28

    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    move-object v11, v0

    check-cast v11, La/b/p/i0$a;

    iget v0, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    const/4 v2, -0x1

    if-ne v0, v2, :cond_28

    iget v12, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    move-result v0

    iput v0, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v3, 0x0

    const/4 v5, 0x0

    move-object/from16 v0, p0

    move v2, v7

    move/from16 v4, p2

    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    iput v12, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    :cond_28
    add-int/lit8 v9, v9, 0x1

    goto :goto_1b

    :cond_29
    move/from16 v27, v5

    move v0, v4

    .line 13
    iput v0, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->getVirtualChildCount()I

    move-result v9

    invoke-static/range {p1 .. p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result v10

    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result v11

    iget-object v0, v6, La/b/p/i0;->j:[I

    const/4 v12, 0x4

    if-eqz v0, :cond_2a

    iget-object v0, v6, La/b/p/i0;->k:[I

    if-nez v0, :cond_2b

    :cond_2a
    new-array v0, v12, [I

    iput-object v0, v6, La/b/p/i0;->j:[I

    new-array v0, v12, [I

    iput-object v0, v6, La/b/p/i0;->k:[I

    :cond_2b
    iget-object v13, v6, La/b/p/i0;->j:[I

    iget-object v14, v6, La/b/p/i0;->k:[I

    const/4 v15, 0x3

    const/4 v0, -0x1

    aput v0, v13, v15

    const/16 v17, 0x2

    aput v0, v13, v17

    aput v0, v13, v27

    const/4 v1, 0x0

    aput v0, v13, v1

    aput v0, v14, v15

    aput v0, v14, v17

    aput v0, v14, v27

    aput v0, v14, v1

    iget-boolean v5, v6, La/b/p/i0;->b:Z

    iget-boolean v4, v6, La/b/p/i0;->i:Z

    const/high16 v0, 0x40000000    # 2.0f

    if-ne v10, v0, :cond_2c

    move/from16 v18, v27

    goto :goto_1c

    :cond_2c
    const/16 v18, 0x0

    :goto_1c
    move/from16 v23, v27

    const/4 v0, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v8, 0x0

    const/4 v12, 0x0

    const/4 v15, 0x0

    const/16 v22, 0x0

    const/16 v24, 0x0

    :goto_1d
    if-ge v3, v9, :cond_40

    .line 14
    invoke-virtual {v6, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v7

    if-nez v7, :cond_2d

    .line 15
    iget v7, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v25

    add-int v7, v25, v7

    iput v7, v6, La/b/p/i0;->g:I

    move/from16 v26, v4

    move/from16 v30, v5

    goto/16 :goto_29

    :cond_2d
    move/from16 v25, v0

    invoke-virtual {v7}, Landroid/view/View;->getVisibility()I

    move-result v0

    move/from16 v26, v2

    const/16 v2, 0x8

    if-ne v0, v2, :cond_2e

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v0

    add-int/2addr v3, v0

    move/from16 v30, v5

    move/from16 v0, v25

    move/from16 v2, v26

    move/from16 v26, v4

    goto/16 :goto_29

    :cond_2e
    invoke-virtual {v6, v3}, La/b/p/i0;->m(I)Z

    move-result v0

    if-eqz v0, :cond_2f

    iget v0, v6, La/b/p/i0;->g:I

    iget v2, v6, La/b/p/i0;->m:I

    add-int/2addr v0, v2

    iput v0, v6, La/b/p/i0;->g:I

    :cond_2f
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    move-object v2, v0

    check-cast v2, La/b/p/i0$a;

    iget v0, v2, La/b/p/i0$a;->a:F

    add-float v29, v1, v0

    const/high16 v1, 0x40000000    # 2.0f

    if-ne v10, v1, :cond_32

    iget v1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    if-nez v1, :cond_32

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-lez v0, :cond_32

    if-eqz v18, :cond_30

    iget v0, v6, La/b/p/i0;->g:I

    iget v1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    move/from16 v30, v3

    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v1, v3

    add-int/2addr v1, v0

    iput v1, v6, La/b/p/i0;->g:I

    goto :goto_1e

    :cond_30
    move/from16 v30, v3

    iget v0, v6, La/b/p/i0;->g:I

    iget v1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v1, v0

    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v1, v3

    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    move-result v0

    iput v0, v6, La/b/p/i0;->g:I

    :goto_1e
    if-eqz v5, :cond_31

    const/4 v0, 0x0

    invoke-static {v0, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v1

    invoke-virtual {v7, v1, v1}, Landroid/view/View;->measure(II)V

    move-object v1, v2

    move/from16 v33, v25

    move/from16 v34, v26

    move/from16 v25, v30

    move/from16 v26, v4

    move/from16 v30, v5

    goto/16 :goto_23

    :cond_31
    move-object v1, v2

    move/from16 v33, v25

    move/from16 v34, v26

    move/from16 v25, v30

    const/high16 v0, 0x40000000    # 2.0f

    move/from16 v26, v4

    move/from16 v30, v5

    move/from16 v5, v27

    goto/16 :goto_24

    :cond_32
    move/from16 v30, v3

    iget v0, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    if-nez v0, :cond_33

    iget v0, v2, La/b/p/i0$a;->a:F

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-lez v0, :cond_34

    const/4 v0, -0x2

    iput v0, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    const/4 v3, 0x0

    goto :goto_1f

    :cond_33
    const/4 v1, 0x0

    :cond_34
    const/high16 v3, -0x80000000

    :goto_1f
    cmpl-float v0, v29, v1

    if-nez v0, :cond_35

    iget v0, v6, La/b/p/i0;->g:I

    move/from16 v31, v0

    goto :goto_20

    :cond_35
    const/16 v31, 0x0

    :goto_20
    const/16 v32, 0x0

    move/from16 v1, v25

    move-object/from16 v0, p0

    move/from16 v33, v1

    move-object v1, v7

    move-object/from16 v35, v2

    move/from16 v34, v26

    move/from16 v2, p1

    move/from16 v36, v3

    move/from16 v25, v30

    move/from16 v3, v31

    move/from16 v26, v4

    move/from16 v4, p2

    move/from16 v30, v5

    move/from16 v5, v32

    invoke-virtual/range {v0 .. v5}, La/b/p/i0;->n(Landroid/view/View;IIII)V

    move/from16 v0, v36

    const/high16 v1, -0x80000000

    if-eq v0, v1, :cond_36

    move-object/from16 v1, v35

    iput v0, v1, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    goto :goto_21

    :cond_36
    move-object/from16 v1, v35

    :goto_21
    invoke-virtual {v7}, Landroid/view/View;->getMeasuredWidth()I

    move-result v0

    iget v2, v6, La/b/p/i0;->g:I

    if-eqz v18, :cond_37

    iget v3, v1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v3, v0

    iget v4, v1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v3, v4

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v4

    add-int/2addr v4, v3

    add-int/2addr v4, v2

    iput v4, v6, La/b/p/i0;->g:I

    goto :goto_22

    :cond_37
    add-int v3, v2, v0

    iget v4, v1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v3, v4

    iget v4, v1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v3, v4

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v4

    add-int/2addr v4, v3

    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    move-result v2

    iput v2, v6, La/b/p/i0;->g:I

    :goto_22
    if-eqz v26, :cond_38

    invoke-static {v0, v8}, Ljava/lang/Math;->max(II)I

    move-result v8

    :cond_38
    :goto_23
    move/from16 v5, v22

    const/high16 v0, 0x40000000    # 2.0f

    :goto_24
    if-eq v11, v0, :cond_39

    iget v0, v1, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v2, -0x1

    if-ne v0, v2, :cond_39

    move/from16 v0, v27

    move/from16 v24, v0

    goto :goto_25

    :cond_39
    const/4 v0, 0x0

    :goto_25
    iget v2, v1, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iget v3, v1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v2, v3

    invoke-virtual {v7}, Landroid/view/View;->getMeasuredHeight()I

    move-result v3

    add-int/2addr v3, v2

    invoke-virtual {v7}, Landroid/view/View;->getMeasuredState()I

    move-result v4

    invoke-static {v12, v4}, Landroid/view/View;->combineMeasuredStates(II)I

    move-result v4

    if-eqz v30, :cond_3b

    invoke-virtual {v7}, Landroid/view/View;->getBaseline()I

    move-result v7

    const/4 v12, -0x1

    if-eq v7, v12, :cond_3b

    iget v12, v1, La/b/p/i0$a;->b:I

    if-gez v12, :cond_3a

    iget v12, v6, La/b/p/i0;->f:I

    :cond_3a
    and-int/lit8 v12, v12, 0x70

    const/16 v21, 0x4

    shr-int/lit8 v12, v12, 0x4

    const/16 v22, -0x2

    and-int/lit8 v12, v12, -0x2

    shr-int/lit8 v12, v12, 0x1

    move/from16 v22, v2

    aget v2, v13, v12

    invoke-static {v2, v7}, Ljava/lang/Math;->max(II)I

    move-result v2

    aput v2, v13, v12

    aget v2, v14, v12

    sub-int v7, v3, v7

    invoke-static {v2, v7}, Ljava/lang/Math;->max(II)I

    move-result v2

    aput v2, v14, v12

    goto :goto_26

    :cond_3b
    move/from16 v22, v2

    :goto_26
    invoke-static {v15, v3}, Ljava/lang/Math;->max(II)I

    move-result v2

    if-eqz v23, :cond_3c

    iget v7, v1, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v12, -0x1

    if-ne v7, v12, :cond_3c

    move/from16 v7, v27

    goto :goto_27

    :cond_3c
    const/4 v7, 0x0

    :goto_27
    iget v1, v1, La/b/p/i0$a;->a:F

    const/4 v12, 0x0

    cmpl-float v1, v1, v12

    if-lez v1, :cond_3e

    if-eqz v0, :cond_3d

    move/from16 v3, v22

    :cond_3d
    move/from16 v1, v33

    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    move-result v0

    goto :goto_28

    :cond_3e
    move/from16 v1, v33

    if-eqz v0, :cond_3f

    move/from16 v3, v22

    :cond_3f
    move/from16 v0, v34

    invoke-static {v0, v3}, Ljava/lang/Math;->max(II)I

    move-result v0

    move/from16 v34, v0

    move v0, v1

    :goto_28
    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v1

    add-int v3, v1, v25

    move v15, v2

    move v12, v4

    move/from16 v22, v5

    move/from16 v23, v7

    move/from16 v1, v29

    move/from16 v2, v34

    :goto_29
    add-int/lit8 v3, v3, 0x1

    move/from16 v7, p1

    move/from16 v4, v26

    move/from16 v5, v30

    goto/16 :goto_1d

    :cond_40
    move/from16 v26, v4

    move/from16 v30, v5

    move/from16 v37, v2

    move v2, v0

    move/from16 v0, v37

    iget v3, v6, La/b/p/i0;->g:I

    if-lez v3, :cond_41

    invoke-virtual {v6, v9}, La/b/p/i0;->m(I)Z

    move-result v3

    if-eqz v3, :cond_41

    iget v3, v6, La/b/p/i0;->g:I

    iget v4, v6, La/b/p/i0;->m:I

    add-int/2addr v3, v4

    iput v3, v6, La/b/p/i0;->g:I

    :cond_41
    aget v3, v13, v27

    const/4 v4, -0x1

    if-ne v3, v4, :cond_43

    const/4 v3, 0x0

    aget v5, v13, v3

    if-ne v5, v4, :cond_43

    aget v3, v13, v17

    if-ne v3, v4, :cond_43

    const/4 v3, 0x3

    aget v5, v13, v3

    if-eq v5, v4, :cond_42

    goto :goto_2a

    :cond_42
    move/from16 v25, v12

    goto :goto_2b

    :cond_43
    const/4 v3, 0x3

    :goto_2a
    aget v4, v13, v3

    const/4 v5, 0x0

    aget v7, v13, v5

    aget v5, v13, v27

    aget v3, v13, v17

    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    invoke-static {v7, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    invoke-static {v4, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    const/4 v4, 0x3

    aget v5, v14, v4

    const/4 v4, 0x0

    aget v7, v14, v4

    aget v4, v14, v27

    move/from16 v25, v12

    aget v12, v14, v17

    invoke-static {v4, v12}, Ljava/lang/Math;->max(II)I

    move-result v4

    invoke-static {v7, v4}, Ljava/lang/Math;->max(II)I

    move-result v4

    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    move-result v4

    add-int/2addr v4, v3

    invoke-static {v15, v4}, Ljava/lang/Math;->max(II)I

    move-result v15

    :goto_2b
    if-eqz v26, :cond_48

    const/high16 v3, -0x80000000

    if-eq v10, v3, :cond_44

    if-nez v10, :cond_48

    :cond_44
    const/4 v3, 0x0

    iput v3, v6, La/b/p/i0;->g:I

    const/4 v4, 0x0

    :goto_2c
    if-ge v4, v9, :cond_48

    .line 16
    invoke-virtual {v6, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    if-nez v3, :cond_45

    .line 17
    iget v3, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->o()I

    move-result v5

    add-int/2addr v5, v3

    iput v5, v6, La/b/p/i0;->g:I

    goto :goto_2e

    :cond_45
    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    move-result v5

    const/16 v7, 0x8

    if-ne v5, v7, :cond_46

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->j()I

    move-result v3

    add-int/2addr v4, v3

    goto :goto_2e

    :cond_46
    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v3

    check-cast v3, La/b/p/i0$a;

    iget v5, v6, La/b/p/i0;->g:I

    if-eqz v18, :cond_47

    iget v7, v3, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v7, v8

    iget v3, v3, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v7, v3

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v3

    add-int/2addr v3, v7

    add-int/2addr v3, v5

    goto :goto_2d

    :cond_47
    add-int v7, v5, v8

    iget v12, v3, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v7, v12

    iget v3, v3, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v7, v3

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v3

    add-int/2addr v3, v7

    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    :goto_2d
    iput v3, v6, La/b/p/i0;->g:I

    :goto_2e
    add-int/lit8 v4, v4, 0x1

    goto :goto_2c

    :cond_48
    iget v3, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v4

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v5

    add-int/2addr v5, v4

    add-int/2addr v5, v3

    iput v5, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getSuggestedMinimumWidth()I

    move-result v3

    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    move/from16 v7, p1

    const/4 v4, 0x0

    invoke-static {v3, v7, v4}, Landroid/view/View;->resolveSizeAndState(III)I

    move-result v3

    const v4, 0xffffff

    and-int/2addr v4, v3

    iget v5, v6, La/b/p/i0;->g:I

    sub-int/2addr v4, v5

    if-nez v22, :cond_4d

    if-eqz v4, :cond_49

    const/4 v12, 0x0

    cmpl-float v16, v1, v12

    if-lez v16, :cond_49

    goto :goto_32

    :cond_49
    invoke-static {v0, v2}, Ljava/lang/Math;->max(II)I

    move-result v0

    if-eqz v26, :cond_4c

    const/high16 v1, 0x40000000    # 2.0f

    if-eq v10, v1, :cond_4c

    const/4 v4, 0x0

    :goto_2f
    if-ge v4, v9, :cond_4c

    .line 18
    invoke-virtual {v6, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    if-eqz v1, :cond_4b

    .line 19
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    move-result v2

    const/16 v10, 0x8

    if-ne v2, v10, :cond_4a

    goto :goto_30

    :cond_4a
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v2

    check-cast v2, La/b/p/i0$a;

    iget v2, v2, La/b/p/i0$a;->a:F

    const/4 v10, 0x0

    cmpl-float v2, v2, v10

    if-lez v2, :cond_4b

    const/high16 v2, 0x40000000    # 2.0f

    invoke-static {v8, v2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v10

    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    move-result v12

    invoke-static {v12, v2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v12

    invoke-virtual {v1, v10, v12}, Landroid/view/View;->measure(II)V

    :cond_4b
    :goto_30
    add-int/lit8 v4, v4, 0x1

    goto :goto_2f

    :cond_4c
    move/from16 v8, p2

    move/from16 v22, v9

    move/from16 v12, v25

    :goto_31
    const/4 v5, 0x0

    goto/16 :goto_3f

    :cond_4d
    :goto_32
    iget v2, v6, La/b/p/i0;->h:F

    const/4 v8, 0x0

    cmpl-float v12, v2, v8

    if-lez v12, :cond_4e

    move v1, v2

    :cond_4e
    const/4 v2, 0x3

    const/4 v8, -0x1

    aput v8, v13, v2

    aput v8, v13, v17

    aput v8, v13, v27

    const/4 v12, 0x0

    aput v8, v13, v12

    aput v8, v14, v2

    aput v8, v14, v17

    aput v8, v14, v27

    aput v8, v14, v12

    iput v12, v6, La/b/p/i0;->g:I

    move v8, v4

    move/from16 v12, v25

    const/4 v2, -0x1

    const/4 v4, 0x0

    :goto_33
    if-ge v4, v9, :cond_5d

    .line 20
    invoke-virtual {v6, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v15

    if-eqz v15, :cond_5c

    .line 21
    invoke-virtual {v15}, Landroid/view/View;->getVisibility()I

    move-result v5

    const/16 v7, 0x8

    if-ne v5, v7, :cond_4f

    goto/16 :goto_3c

    :cond_4f
    invoke-virtual {v15}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v5

    check-cast v5, La/b/p/i0$a;

    iget v7, v5, La/b/p/i0$a;->a:F

    const/16 v20, 0x0

    cmpl-float v22, v7, v20

    if-lez v22, :cond_54

    move/from16 v22, v9

    int-to-float v9, v8

    mul-float/2addr v9, v7

    div-float/2addr v9, v1

    float-to-int v9, v9

    sub-float/2addr v1, v7

    sub-int/2addr v8, v9

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v7

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v25

    add-int v25, v25, v7

    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    add-int v25, v25, v7

    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int v7, v25, v7

    move/from16 v25, v1

    iget v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    move/from16 v26, v8

    move/from16 v8, p2

    invoke-static {v8, v7, v1}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v1

    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    if-nez v7, :cond_51

    const/high16 v7, 0x40000000    # 2.0f

    if-eq v10, v7, :cond_50

    goto :goto_34

    :cond_50
    if-lez v9, :cond_52

    move v7, v9

    goto :goto_35

    :cond_51
    :goto_34
    invoke-virtual {v15}, Landroid/view/View;->getMeasuredWidth()I

    move-result v7

    add-int/2addr v7, v9

    if-gez v7, :cond_53

    :cond_52
    const/4 v7, 0x0

    :cond_53
    :goto_35
    const/high16 v9, 0x40000000    # 2.0f

    invoke-static {v7, v9}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v7

    invoke-virtual {v15, v7, v1}, Landroid/view/View;->measure(II)V

    invoke-virtual {v15}, Landroid/view/View;->getMeasuredState()I

    move-result v1

    const/high16 v7, -0x1000000

    and-int/2addr v1, v7

    invoke-static {v12, v1}, Landroid/view/View;->combineMeasuredStates(II)I

    move-result v12

    move/from16 v1, v25

    move/from16 v7, v26

    goto :goto_36

    :cond_54
    move v7, v8

    move/from16 v22, v9

    move/from16 v8, p2

    :goto_36
    if-eqz v18, :cond_55

    iget v9, v6, La/b/p/i0;->g:I

    invoke-virtual {v15}, Landroid/view/View;->getMeasuredWidth()I

    move-result v25

    move/from16 v26, v1

    iget v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int v25, v25, v1

    iget v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int v25, v25, v1

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v1

    add-int v1, v1, v25

    add-int/2addr v1, v9

    move/from16 v25, v7

    goto :goto_37

    :cond_55
    move/from16 v26, v1

    iget v1, v6, La/b/p/i0;->g:I

    invoke-virtual {v15}, Landroid/view/View;->getMeasuredWidth()I

    move-result v9

    add-int/2addr v9, v1

    move/from16 v25, v7

    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    add-int/2addr v9, v7

    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    add-int/2addr v9, v7

    invoke-virtual/range {p0 .. p0}, La/b/p/i0;->l()I

    move-result v7

    add-int/2addr v7, v9

    invoke-static {v1, v7}, Ljava/lang/Math;->max(II)I

    move-result v1

    :goto_37
    iput v1, v6, La/b/p/i0;->g:I

    const/high16 v1, 0x40000000    # 2.0f

    if-eq v11, v1, :cond_56

    iget v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v7, -0x1

    if-ne v1, v7, :cond_56

    move/from16 v1, v27

    goto :goto_38

    :cond_56
    const/4 v1, 0x0

    :goto_38
    iget v7, v5, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iget v9, v5, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    add-int/2addr v7, v9

    invoke-virtual {v15}, Landroid/view/View;->getMeasuredHeight()I

    move-result v9

    add-int/2addr v9, v7

    invoke-static {v2, v9}, Ljava/lang/Math;->max(II)I

    move-result v2

    if-eqz v1, :cond_57

    goto :goto_39

    :cond_57
    move v7, v9

    :goto_39
    invoke-static {v0, v7}, Ljava/lang/Math;->max(II)I

    move-result v0

    if-eqz v23, :cond_58

    iget v1, v5, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v7, -0x1

    if-ne v1, v7, :cond_59

    move/from16 v1, v27

    goto :goto_3a

    :cond_58
    const/4 v7, -0x1

    :cond_59
    const/4 v1, 0x0

    :goto_3a
    if-eqz v30, :cond_5b

    invoke-virtual {v15}, Landroid/view/View;->getBaseline()I

    move-result v15

    if-eq v15, v7, :cond_5b

    iget v5, v5, La/b/p/i0$a;->b:I

    if-gez v5, :cond_5a

    iget v5, v6, La/b/p/i0;->f:I

    :cond_5a
    and-int/lit8 v5, v5, 0x70

    const/16 v21, 0x4

    shr-int/lit8 v5, v5, 0x4

    const/16 v28, -0x2

    and-int/lit8 v5, v5, -0x2

    shr-int/lit8 v5, v5, 0x1

    aget v7, v13, v5

    invoke-static {v7, v15}, Ljava/lang/Math;->max(II)I

    move-result v7

    aput v7, v13, v5

    aget v7, v14, v5

    sub-int/2addr v9, v15

    invoke-static {v7, v9}, Ljava/lang/Math;->max(II)I

    move-result v7

    aput v7, v14, v5

    goto :goto_3b

    :cond_5b
    const/16 v21, 0x4

    const/16 v28, -0x2

    :goto_3b
    move/from16 v23, v1

    move/from16 v7, v25

    move/from16 v1, v26

    goto :goto_3d

    :cond_5c
    :goto_3c
    move v7, v8

    move/from16 v22, v9

    const/16 v20, 0x0

    const/16 v21, 0x4

    const/16 v28, -0x2

    move/from16 v8, p2

    :goto_3d
    add-int/lit8 v4, v4, 0x1

    move v8, v7

    move/from16 v9, v22

    move/from16 v7, p1

    goto/16 :goto_33

    :cond_5d
    move/from16 v8, p2

    move/from16 v22, v9

    iget v1, v6, La/b/p/i0;->g:I

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingLeft()I

    move-result v4

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingRight()I

    move-result v5

    add-int/2addr v5, v4

    add-int/2addr v5, v1

    iput v5, v6, La/b/p/i0;->g:I

    aget v1, v13, v27

    const/4 v4, -0x1

    if-ne v1, v4, :cond_5f

    const/4 v1, 0x0

    aget v5, v13, v1

    if-ne v5, v4, :cond_5f

    aget v1, v13, v17

    if-ne v1, v4, :cond_5f

    const/4 v1, 0x3

    aget v5, v13, v1

    if-eq v5, v4, :cond_5e

    goto :goto_3e

    :cond_5e
    move v15, v2

    goto/16 :goto_31

    :cond_5f
    const/4 v1, 0x3

    :goto_3e
    aget v4, v13, v1

    const/4 v5, 0x0

    aget v7, v13, v5

    aget v9, v13, v27

    aget v10, v13, v17

    invoke-static {v9, v10}, Ljava/lang/Math;->max(II)I

    move-result v9

    invoke-static {v7, v9}, Ljava/lang/Math;->max(II)I

    move-result v7

    invoke-static {v4, v7}, Ljava/lang/Math;->max(II)I

    move-result v4

    aget v1, v14, v1

    aget v7, v14, v5

    aget v9, v14, v27

    aget v10, v14, v17

    invoke-static {v9, v10}, Ljava/lang/Math;->max(II)I

    move-result v9

    invoke-static {v7, v9}, Ljava/lang/Math;->max(II)I

    move-result v7

    invoke-static {v1, v7}, Ljava/lang/Math;->max(II)I

    move-result v1

    add-int/2addr v1, v4

    invoke-static {v2, v1}, Ljava/lang/Math;->max(II)I

    move-result v1

    move v15, v1

    :goto_3f
    if-nez v23, :cond_60

    const/high16 v1, 0x40000000    # 2.0f

    if-eq v11, v1, :cond_60

    goto :goto_40

    :cond_60
    move v0, v15

    :goto_40
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingTop()I

    move-result v1

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getPaddingBottom()I

    move-result v2

    add-int/2addr v2, v1

    add-int/2addr v2, v0

    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getSuggestedMinimumHeight()I

    move-result v0

    invoke-static {v2, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    const/high16 v1, -0x1000000

    and-int/2addr v1, v12

    or-int/2addr v1, v3

    shl-int/lit8 v2, v12, 0x10

    invoke-static {v0, v8, v2}, Landroid/view/View;->resolveSizeAndState(III)I

    move-result v0

    invoke-virtual {v6, v1, v0}, Landroid/view/ViewGroup;->setMeasuredDimension(II)V

    if-eqz v24, :cond_63

    .line 22
    invoke-virtual/range {p0 .. p0}, Landroid/view/ViewGroup;->getMeasuredHeight()I

    move-result v0

    const/high16 v1, 0x40000000    # 2.0f

    invoke-static {v0, v1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v7

    move v8, v5

    move/from16 v9, v22

    :goto_41
    if-ge v8, v9, :cond_63

    .line 23
    invoke-virtual {v6, v8}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    .line 24
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    move-result v0

    const/16 v10, 0x8

    if-eq v0, v10, :cond_61

    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    move-object v11, v0

    check-cast v11, La/b/p/i0$a;

    iget v0, v11, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    const/4 v12, -0x1

    if-ne v0, v12, :cond_62

    iget v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    move-result v0

    iput v0, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    const/4 v3, 0x0

    const/4 v5, 0x0

    move-object/from16 v0, p0

    move/from16 v2, p1

    move v4, v7

    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    iput v13, v11, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    goto :goto_42

    :cond_61
    const/4 v12, -0x1

    :cond_62
    :goto_42
    add-int/lit8 v8, v8, 0x1

    goto :goto_41

    :cond_63
    return-void
.end method

.method public setBaselineAligned(Z)V
    .locals 0

    iput-boolean p1, p0, La/b/p/i0;->b:Z

    return-void
.end method

.method public setBaselineAlignedChildIndex(I)V
    .locals 2

    if-ltz p1, :cond_0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    if-ge p1, v0, :cond_0

    iput p1, p0, La/b/p/i0;->c:I

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "base aligned child index out of range (0, "

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public setDividerDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    iget-object v0, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    iput-object p1, p0, La/b/p/i0;->l:Landroid/graphics/drawable/Drawable;

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    move-result v1

    iput v1, p0, La/b/p/i0;->m:I

    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    move-result v1

    iput v1, p0, La/b/p/i0;->n:I

    goto :goto_0

    :cond_1
    iput v0, p0, La/b/p/i0;->m:I

    iput v0, p0, La/b/p/i0;->n:I

    :goto_0
    if-nez p1, :cond_2

    const/4 v0, 0x1

    :cond_2
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->setWillNotDraw(Z)V

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    return-void
.end method

.method public setDividerPadding(I)V
    .locals 0

    iput p1, p0, La/b/p/i0;->p:I

    return-void
.end method

.method public setGravity(I)V
    .locals 1

    iget v0, p0, La/b/p/i0;->f:I

    if-eq v0, p1, :cond_2

    const v0, 0x800007

    and-int/2addr v0, p1

    if-nez v0, :cond_0

    const v0, 0x800003

    or-int/2addr p1, v0

    :cond_0
    and-int/lit8 v0, p1, 0x70

    if-nez v0, :cond_1

    or-int/lit8 p1, p1, 0x30

    :cond_1
    iput p1, p0, La/b/p/i0;->f:I

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    :cond_2
    return-void
.end method

.method public setHorizontalGravity(I)V
    .locals 2

    const v0, 0x800007

    and-int/2addr p1, v0

    iget v1, p0, La/b/p/i0;->f:I

    and-int/2addr v0, v1

    if-eq v0, p1, :cond_0

    const v0, -0x800008

    and-int/2addr v0, v1

    or-int/2addr p1, v0

    iput p1, p0, La/b/p/i0;->f:I

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    :cond_0
    return-void
.end method

.method public setMeasureWithLargestChildEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, La/b/p/i0;->i:Z

    return-void
.end method

.method public setOrientation(I)V
    .locals 1

    iget v0, p0, La/b/p/i0;->e:I

    if-eq v0, p1, :cond_0

    iput p1, p0, La/b/p/i0;->e:I

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    :cond_0
    return-void
.end method

.method public setShowDividers(I)V
    .locals 1

    iget v0, p0, La/b/p/i0;->o:I

    if-eq p1, v0, :cond_0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    :cond_0
    iput p1, p0, La/b/p/i0;->o:I

    return-void
.end method

.method public setVerticalGravity(I)V
    .locals 2

    and-int/lit8 p1, p1, 0x70

    iget v0, p0, La/b/p/i0;->f:I

    and-int/lit8 v1, v0, 0x70

    if-eq v1, p1, :cond_0

    and-int/lit8 v0, v0, -0x71

    or-int/2addr p1, v0

    iput p1, p0, La/b/p/i0;->f:I

    invoke-virtual {p0}, Landroid/view/ViewGroup;->requestLayout()V

    :cond_0
    return-void
.end method

.method public setWeightSum(F)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0, p1}, Ljava/lang/Math;->max(FF)F

    move-result p1

    iput p1, p0, La/b/p/i0;->h:F

    return-void
.end method

.method public shouldDelayChildPressedState()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
