.class public Landroidx/constraintlayout/widget/ConstraintLayout$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/e/b/h/l/b$b;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/constraintlayout/widget/ConstraintLayout;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "b"
.end annotation


# instance fields
.field public a:Landroidx/constraintlayout/widget/ConstraintLayout;

.field public b:I

.field public c:I

.field public d:I

.field public e:I

.field public f:I

.field public g:I

.field public final synthetic h:Landroidx/constraintlayout/widget/ConstraintLayout;


# direct methods
.method public constructor <init>(Landroidx/constraintlayout/widget/ConstraintLayout;Landroidx/constraintlayout/widget/ConstraintLayout;)V
    .locals 0

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->h:Landroidx/constraintlayout/widget/ConstraintLayout;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->a:Landroidx/constraintlayout/widget/ConstraintLayout;

    return-void
.end method


# virtual methods
.method public final a(III)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p1, p2, :cond_0

    return v0

    :cond_0
    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result v1

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result p1

    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result p2

    const/high16 v2, 0x40000000    # 2.0f

    if-ne p1, v2, :cond_2

    const/high16 p1, -0x80000000

    if-eq v1, p1, :cond_1

    if-nez v1, :cond_2

    :cond_1
    if-ne p3, p2, :cond_2

    return v0

    :cond_2
    const/4 p1, 0x0

    return p1
.end method

.method public final b(La/e/b/h/d;La/e/b/h/l/b$a;)V
    .locals 18
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "WrongCall"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    sget-object v3, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v4, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v5, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    if-nez v1, :cond_0

    return-void

    .line 1
    :cond_0
    iget v6, v1, La/e/b/h/d;->e0:I

    const/16 v7, 0x8

    const/4 v8, 0x0

    if-ne v6, v7, :cond_1

    .line 2
    iget-boolean v6, v1, La/e/b/h/d;->B:Z

    if-nez v6, :cond_1

    .line 3
    iput v8, v2, La/e/b/h/l/b$a;->e:I

    iput v8, v2, La/e/b/h/l/b$a;->f:I

    iput v8, v2, La/e/b/h/l/b$a;->g:I

    return-void

    .line 4
    :cond_1
    iget-object v6, v1, La/e/b/h/d;->R:La/e/b/h/d;

    if-nez v6, :cond_2

    return-void

    .line 5
    :cond_2
    iget-object v6, v2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    iget-object v7, v2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    iget v9, v2, La/e/b/h/l/b$a;->c:I

    iget v10, v2, La/e/b/h/l/b$a;->d:I

    iget v11, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->b:I

    iget v12, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->c:I

    add-int/2addr v11, v12

    iget v12, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->d:I

    .line 6
    iget-object v13, v1, La/e/b/h/d;->d0:Ljava/lang/Object;

    .line 7
    check-cast v13, Landroid/view/View;

    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v14

    const/4 v8, 0x2

    const/4 v15, 0x1

    if-eqz v14, :cond_f

    if-eq v14, v15, :cond_e

    if-eq v14, v8, :cond_6

    const/4 v9, 0x3

    if-eq v14, v9, :cond_3

    const/4 v8, 0x0

    goto/16 :goto_6

    :cond_3
    iget v9, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->f:I

    .line 8
    iget-object v14, v1, La/e/b/h/d;->F:La/e/b/h/c;

    if-eqz v14, :cond_4

    iget v14, v14, La/e/b/h/c;->g:I

    const/16 v16, 0x0

    add-int/lit8 v14, v14, 0x0

    goto :goto_0

    :cond_4
    const/4 v14, 0x0

    :goto_0
    iget-object v8, v1, La/e/b/h/d;->H:La/e/b/h/c;

    if-eqz v8, :cond_5

    iget v8, v8, La/e/b/h/c;->g:I

    add-int/2addr v14, v8

    :cond_5
    add-int/2addr v12, v14

    const/4 v8, -0x1

    .line 9
    invoke-static {v9, v12, v8}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v9

    move v8, v9

    goto :goto_6

    :cond_6
    iget v8, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->f:I

    const/4 v9, -0x2

    invoke-static {v8, v12, v9}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v8

    iget v9, v1, La/e/b/h/d;->n:I

    if-ne v9, v15, :cond_7

    move v9, v15

    goto :goto_1

    :cond_7
    const/4 v9, 0x0

    :goto_1
    iget v12, v2, La/e/b/h/l/b$a;->j:I

    const/4 v14, 0x2

    if-eq v12, v15, :cond_9

    if-ne v12, v14, :cond_8

    goto :goto_2

    :cond_8
    const/high16 v14, 0x40000000    # 2.0f

    goto :goto_6

    :cond_9
    :goto_2
    invoke-virtual {v13}, Landroid/view/View;->getMeasuredHeight()I

    move-result v12

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v15

    if-ne v12, v15, :cond_a

    const/4 v12, 0x1

    goto :goto_3

    :cond_a
    const/4 v12, 0x0

    :goto_3
    iget v15, v2, La/e/b/h/l/b$a;->j:I

    if-eq v15, v14, :cond_d

    if-eqz v9, :cond_d

    if-eqz v9, :cond_b

    if-nez v12, :cond_d

    :cond_b
    instance-of v9, v13, La/e/c/i;

    if-nez v9, :cond_d

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->z()Z

    move-result v9

    if-eqz v9, :cond_c

    goto :goto_4

    :cond_c
    const/4 v9, 0x0

    goto :goto_5

    :cond_d
    :goto_4
    const/4 v9, 0x1

    :goto_5
    if-eqz v9, :cond_8

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v8

    const/high16 v14, 0x40000000    # 2.0f

    invoke-static {v8, v14}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v8

    goto :goto_6

    :cond_e
    const/high16 v14, 0x40000000    # 2.0f

    iget v8, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->f:I

    const/4 v9, -0x2

    invoke-static {v8, v12, v9}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v8

    goto :goto_6

    :cond_f
    const/high16 v14, 0x40000000    # 2.0f

    invoke-static {v9, v14}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v8

    :goto_6
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    move-result v9

    if-eqz v9, :cond_1c

    const/4 v12, 0x1

    if-eq v9, v12, :cond_1b

    const/4 v10, 0x2

    if-eq v9, v10, :cond_13

    const/4 v10, 0x3

    if-eq v9, v10, :cond_10

    const/4 v9, 0x0

    goto/16 :goto_e

    :cond_10
    iget v9, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->g:I

    .line 10
    iget-object v10, v1, La/e/b/h/d;->F:La/e/b/h/c;

    if-eqz v10, :cond_11

    iget-object v10, v1, La/e/b/h/d;->G:La/e/b/h/c;

    iget v10, v10, La/e/b/h/c;->g:I

    const/4 v12, 0x0

    add-int/2addr v10, v12

    goto :goto_7

    :cond_11
    const/4 v10, 0x0

    :goto_7
    iget-object v12, v1, La/e/b/h/d;->H:La/e/b/h/c;

    if-eqz v12, :cond_12

    iget-object v12, v1, La/e/b/h/d;->I:La/e/b/h/c;

    iget v12, v12, La/e/b/h/c;->g:I

    add-int/2addr v10, v12

    :cond_12
    add-int/2addr v11, v10

    const/4 v10, -0x1

    const/high16 v12, 0x40000000    # 2.0f

    goto :goto_d

    .line 11
    :cond_13
    iget v9, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->g:I

    const/4 v10, -0x2

    invoke-static {v9, v11, v10}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v9

    iget v10, v1, La/e/b/h/d;->o:I

    const/4 v11, 0x1

    if-ne v10, v11, :cond_14

    move v10, v11

    goto :goto_8

    :cond_14
    const/4 v10, 0x0

    :goto_8
    iget v12, v2, La/e/b/h/l/b$a;->j:I

    if-eq v12, v11, :cond_16

    const/4 v11, 0x2

    if-ne v12, v11, :cond_15

    goto :goto_9

    :cond_15
    const/high16 v12, 0x40000000    # 2.0f

    goto :goto_e

    :cond_16
    const/4 v11, 0x2

    :goto_9
    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v12

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v14

    if-ne v12, v14, :cond_17

    const/4 v12, 0x1

    goto :goto_a

    :cond_17
    const/4 v12, 0x0

    :goto_a
    iget v14, v2, La/e/b/h/l/b$a;->j:I

    if-eq v14, v11, :cond_1a

    if-eqz v10, :cond_1a

    if-eqz v10, :cond_18

    if-nez v12, :cond_1a

    :cond_18
    instance-of v10, v13, La/e/c/i;

    if-nez v10, :cond_1a

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->A()Z

    move-result v10

    if-eqz v10, :cond_19

    goto :goto_b

    :cond_19
    const/4 v10, 0x0

    goto :goto_c

    :cond_1a
    :goto_b
    const/4 v10, 0x1

    :goto_c
    if-eqz v10, :cond_15

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v9

    const/high16 v12, 0x40000000    # 2.0f

    invoke-static {v9, v12}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v9

    goto :goto_e

    :cond_1b
    const/4 v10, -0x2

    const/high16 v12, 0x40000000    # 2.0f

    iget v9, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->g:I

    :goto_d
    invoke-static {v9, v11, v10}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    move-result v9

    goto :goto_e

    :cond_1c
    const/high16 v12, 0x40000000    # 2.0f

    invoke-static {v10, v12}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v9

    .line 12
    :goto_e
    iget-object v10, v1, La/e/b/h/d;->R:La/e/b/h/d;

    .line 13
    check-cast v10, La/e/b/h/e;

    if-eqz v10, :cond_1e

    iget-object v11, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->h:Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 14
    iget v11, v11, Landroidx/constraintlayout/widget/ConstraintLayout;->j:I

    const/16 v12, 0x100

    .line 15
    invoke-static {v11, v12}, La/e/b/h/i;->b(II)Z

    move-result v11

    if-eqz v11, :cond_1e

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v11

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v12

    if-ne v11, v12, :cond_1e

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v11

    invoke-virtual {v10}, La/e/b/h/d;->r()I

    move-result v12

    if-ge v11, v12, :cond_1e

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredHeight()I

    move-result v11

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v12

    if-ne v11, v12, :cond_1e

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredHeight()I

    move-result v11

    invoke-virtual {v10}, La/e/b/h/d;->l()I

    move-result v10

    if-ge v11, v10, :cond_1e

    invoke-virtual {v13}, Landroid/view/View;->getBaseline()I

    move-result v10

    .line 16
    iget v11, v1, La/e/b/h/d;->Y:I

    if-ne v10, v11, :cond_1e

    .line 17
    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->y()Z

    move-result v10

    if-nez v10, :cond_1e

    .line 18
    iget v10, v1, La/e/b/h/d;->D:I

    .line 19
    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v11

    invoke-virtual {v0, v10, v8, v11}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->a(III)Z

    move-result v10

    if-eqz v10, :cond_1d

    .line 20
    iget v10, v1, La/e/b/h/d;->E:I

    .line 21
    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v11

    invoke-virtual {v0, v10, v9, v11}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->a(III)Z

    move-result v10

    if-eqz v10, :cond_1d

    const/4 v10, 0x1

    goto :goto_f

    :cond_1d
    const/4 v10, 0x0

    :goto_f
    if-eqz v10, :cond_1e

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v3

    iput v3, v2, La/e/b/h/l/b$a;->e:I

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v3

    iput v3, v2, La/e/b/h/l/b$a;->f:I

    .line 22
    iget v1, v1, La/e/b/h/d;->Y:I

    .line 23
    iput v1, v2, La/e/b/h/l/b$a;->g:I

    return-void

    :cond_1e
    if-ne v6, v5, :cond_1f

    const/4 v10, 0x1

    goto :goto_10

    :cond_1f
    const/4 v10, 0x0

    :goto_10
    if-ne v7, v5, :cond_20

    const/4 v5, 0x1

    goto :goto_11

    :cond_20
    const/4 v5, 0x0

    :goto_11
    if-eq v7, v4, :cond_22

    if-ne v7, v3, :cond_21

    goto :goto_12

    :cond_21
    const/4 v7, 0x0

    goto :goto_13

    :cond_22
    :goto_12
    const/4 v7, 0x1

    :goto_13
    if-eq v6, v4, :cond_24

    if-ne v6, v3, :cond_23

    goto :goto_14

    :cond_23
    const/4 v3, 0x0

    goto :goto_15

    :cond_24
    :goto_14
    const/4 v3, 0x1

    :goto_15
    const/4 v4, 0x0

    if-eqz v10, :cond_25

    iget v6, v1, La/e/b/h/d;->U:F

    cmpl-float v6, v6, v4

    if-lez v6, :cond_25

    const/4 v6, 0x1

    goto :goto_16

    :cond_25
    const/4 v6, 0x0

    :goto_16
    if-eqz v5, :cond_26

    iget v11, v1, La/e/b/h/d;->U:F

    cmpl-float v4, v11, v4

    if-lez v4, :cond_26

    const/4 v4, 0x1

    goto :goto_17

    :cond_26
    const/4 v4, 0x0

    :goto_17
    if-nez v13, :cond_27

    return-void

    :cond_27
    invoke-virtual {v13}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v11

    check-cast v11, Landroidx/constraintlayout/widget/ConstraintLayout$a;

    iget v12, v2, La/e/b/h/l/b$a;->j:I

    const/4 v14, 0x1

    if-eq v12, v14, :cond_29

    const/4 v14, 0x2

    if-eq v12, v14, :cond_29

    if-eqz v10, :cond_29

    iget v10, v1, La/e/b/h/d;->n:I

    if-nez v10, :cond_29

    if-eqz v5, :cond_29

    iget v5, v1, La/e/b/h/d;->o:I

    if-eqz v5, :cond_28

    goto :goto_18

    :cond_28
    const/4 v0, 0x0

    const/4 v3, 0x0

    const/4 v4, -0x1

    const/4 v14, 0x0

    const/4 v15, 0x0

    goto/16 :goto_20

    :cond_29
    :goto_18
    instance-of v5, v13, La/e/c/l;

    if-eqz v5, :cond_2a

    instance-of v5, v1, La/e/b/h/j;

    if-eqz v5, :cond_2a

    move-object v5, v1

    check-cast v5, La/e/b/h/j;

    move-object v5, v13

    check-cast v5, La/e/c/l;

    invoke-virtual {v5}, La/e/c/l;->k()V

    goto :goto_19

    :cond_2a
    invoke-virtual {v13, v8, v9}, Landroid/view/View;->measure(II)V

    .line 24
    :goto_19
    iput v8, v1, La/e/b/h/d;->D:I

    iput v9, v1, La/e/b/h/d;->E:I

    const/4 v5, 0x0

    .line 25
    iput-boolean v5, v1, La/e/b/h/d;->g:Z

    .line 26
    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v5

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredHeight()I

    move-result v10

    invoke-virtual {v13}, Landroid/view/View;->getBaseline()I

    move-result v12

    iget v14, v1, La/e/b/h/d;->q:I

    if-lez v14, :cond_2b

    invoke-static {v14, v5}, Ljava/lang/Math;->max(II)I

    move-result v14

    goto :goto_1a

    :cond_2b
    move v14, v5

    :goto_1a
    iget v15, v1, La/e/b/h/d;->r:I

    if-lez v15, :cond_2c

    invoke-static {v15, v14}, Ljava/lang/Math;->min(II)I

    move-result v14

    :cond_2c
    iget v15, v1, La/e/b/h/d;->t:I

    if-lez v15, :cond_2d

    invoke-static {v15, v10}, Ljava/lang/Math;->max(II)I

    move-result v15

    move/from16 v17, v8

    goto :goto_1b

    :cond_2d
    move/from16 v17, v8

    move v15, v10

    :goto_1b
    iget v8, v1, La/e/b/h/d;->u:I

    if-lez v8, :cond_2e

    invoke-static {v8, v15}, Ljava/lang/Math;->min(II)I

    move-result v15

    :cond_2e
    iget-object v8, v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;->h:Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 27
    iget v8, v8, Landroidx/constraintlayout/widget/ConstraintLayout;->j:I

    const/4 v0, 0x1

    .line 28
    invoke-static {v8, v0}, La/e/b/h/i;->b(II)Z

    move-result v8

    if-nez v8, :cond_30

    const/high16 v0, 0x3f000000    # 0.5f

    if-eqz v6, :cond_2f

    if-eqz v7, :cond_2f

    iget v3, v1, La/e/b/h/d;->U:F

    int-to-float v4, v15

    mul-float/2addr v4, v3

    add-float/2addr v4, v0

    float-to-int v14, v4

    goto :goto_1c

    :cond_2f
    if-eqz v4, :cond_30

    if-eqz v3, :cond_30

    iget v3, v1, La/e/b/h/d;->U:F

    int-to-float v4, v14

    div-float/2addr v4, v3

    add-float/2addr v4, v0

    float-to-int v15, v4

    :cond_30
    :goto_1c
    if-ne v5, v14, :cond_32

    if-eq v10, v15, :cond_31

    goto :goto_1d

    :cond_31
    move/from16 v16, v12

    const/4 v0, 0x0

    goto :goto_1f

    :cond_32
    :goto_1d
    const/high16 v0, 0x40000000    # 2.0f

    if-eq v5, v14, :cond_33

    invoke-static {v14, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v8

    goto :goto_1e

    :cond_33
    move/from16 v8, v17

    :goto_1e
    if-eq v10, v15, :cond_34

    invoke-static {v15, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v9

    :cond_34
    invoke-virtual {v13, v8, v9}, Landroid/view/View;->measure(II)V

    .line 29
    iput v8, v1, La/e/b/h/d;->D:I

    iput v9, v1, La/e/b/h/d;->E:I

    const/4 v0, 0x0

    .line 30
    iput-boolean v0, v1, La/e/b/h/d;->g:Z

    .line 31
    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v3

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredHeight()I

    move-result v4

    invoke-virtual {v13}, Landroid/view/View;->getBaseline()I

    move-result v5

    move v14, v3

    move v15, v4

    move/from16 v16, v5

    :goto_1f
    move/from16 v3, v16

    const/4 v4, -0x1

    :goto_20
    if-eq v3, v4, :cond_35

    const/16 v16, 0x1

    goto :goto_21

    :cond_35
    move/from16 v16, v0

    :goto_21
    iget v4, v2, La/e/b/h/l/b$a;->c:I

    if-ne v14, v4, :cond_37

    iget v4, v2, La/e/b/h/l/b$a;->d:I

    if-eq v15, v4, :cond_36

    goto :goto_22

    :cond_36
    move v8, v0

    goto :goto_23

    :cond_37
    :goto_22
    const/4 v8, 0x1

    :goto_23
    iput-boolean v8, v2, La/e/b/h/l/b$a;->i:Z

    iget-boolean v0, v11, Landroidx/constraintlayout/widget/ConstraintLayout$a;->X:Z

    if-eqz v0, :cond_38

    const/4 v12, 0x1

    goto :goto_24

    :cond_38
    move/from16 v12, v16

    :goto_24
    if-eqz v12, :cond_39

    const/4 v0, -0x1

    if-eq v3, v0, :cond_39

    .line 32
    iget v0, v1, La/e/b/h/d;->Y:I

    if-eq v0, v3, :cond_39

    const/4 v0, 0x1

    .line 33
    iput-boolean v0, v2, La/e/b/h/l/b$a;->i:Z

    :cond_39
    iput v14, v2, La/e/b/h/l/b$a;->e:I

    iput v15, v2, La/e/b/h/l/b$a;->f:I

    iput-boolean v12, v2, La/e/b/h/l/b$a;->h:Z

    iput v3, v2, La/e/b/h/l/b$a;->g:I

    return-void
.end method
