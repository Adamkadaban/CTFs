.class public La/e/b/h/e;
.super La/e/b/h/k;
.source ""


# instance fields
.field public A0:I

.field public B0:Z

.field public C0:Z

.field public D0:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "La/e/b/h/c;",
            ">;"
        }
    .end annotation
.end field

.field public E0:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "La/e/b/h/c;",
            ">;"
        }
    .end annotation
.end field

.field public F0:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "La/e/b/h/c;",
            ">;"
        }
    .end annotation
.end field

.field public G0:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "La/e/b/h/c;",
            ">;"
        }
    .end annotation
.end field

.field public H0:La/e/b/h/l/b$a;

.field public p0:La/e/b/h/l/b;

.field public q0:La/e/b/h/l/e;

.field public r0:La/e/b/h/l/b$b;

.field public s0:Z

.field public t0:La/e/b/d;

.field public u0:I

.field public v0:I

.field public w0:I

.field public x0:I

.field public y0:[La/e/b/h/b;

.field public z0:[La/e/b/h/b;


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, La/e/b/h/k;-><init>()V

    new-instance v0, La/e/b/h/l/b;

    invoke-direct {v0, p0}, La/e/b/h/l/b;-><init>(La/e/b/h/e;)V

    iput-object v0, p0, La/e/b/h/e;->p0:La/e/b/h/l/b;

    new-instance v0, La/e/b/h/l/e;

    invoke-direct {v0, p0}, La/e/b/h/l/e;-><init>(La/e/b/h/e;)V

    iput-object v0, p0, La/e/b/h/e;->q0:La/e/b/h/l/e;

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/e;->r0:La/e/b/h/l/b$b;

    const/4 v1, 0x0

    iput-boolean v1, p0, La/e/b/h/e;->s0:Z

    new-instance v2, La/e/b/d;

    invoke-direct {v2}, La/e/b/d;-><init>()V

    iput-object v2, p0, La/e/b/h/e;->t0:La/e/b/d;

    iput v1, p0, La/e/b/h/e;->w0:I

    iput v1, p0, La/e/b/h/e;->x0:I

    const/4 v2, 0x4

    new-array v3, v2, [La/e/b/h/b;

    iput-object v3, p0, La/e/b/h/e;->y0:[La/e/b/h/b;

    new-array v2, v2, [La/e/b/h/b;

    iput-object v2, p0, La/e/b/h/e;->z0:[La/e/b/h/b;

    const/16 v2, 0x101

    iput v2, p0, La/e/b/h/e;->A0:I

    iput-boolean v1, p0, La/e/b/h/e;->B0:Z

    iput-boolean v1, p0, La/e/b/h/e;->C0:Z

    iput-object v0, p0, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    iput-object v0, p0, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    iput-object v0, p0, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    iput-object v0, p0, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    new-instance v0, La/e/b/h/l/b$a;

    invoke-direct {v0}, La/e/b/h/l/b$a;-><init>()V

    iput-object v0, p0, La/e/b/h/e;->H0:La/e/b/h/l/b$a;

    return-void
.end method

.method public static X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z
    .locals 9

    sget-object v0, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    const/4 v3, 0x0

    if-nez p1, :cond_0

    return v3

    :cond_0
    invoke-virtual {p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v4

    iput-object v4, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    invoke-virtual {p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v4

    iput-object v4, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    invoke-virtual {p0}, La/e/b/h/d;->r()I

    move-result v4

    iput v4, p2, La/e/b/h/l/b$a;->c:I

    invoke-virtual {p0}, La/e/b/h/d;->l()I

    move-result v4

    iput v4, p2, La/e/b/h/l/b$a;->d:I

    iput-boolean v3, p2, La/e/b/h/l/b$a;->i:Z

    iput p3, p2, La/e/b/h/l/b$a;->j:I

    iget-object p3, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    const/4 v4, 0x1

    if-ne p3, v0, :cond_1

    move p3, v4

    goto :goto_0

    :cond_1
    move p3, v3

    :goto_0
    iget-object v5, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    if-ne v5, v0, :cond_2

    move v0, v4

    goto :goto_1

    :cond_2
    move v0, v3

    :goto_1
    const/4 v5, 0x0

    if-eqz p3, :cond_3

    iget v6, p0, La/e/b/h/d;->U:F

    cmpl-float v6, v6, v5

    if-lez v6, :cond_3

    move v6, v4

    goto :goto_2

    :cond_3
    move v6, v3

    :goto_2
    if-eqz v0, :cond_4

    iget v7, p0, La/e/b/h/d;->U:F

    cmpl-float v5, v7, v5

    if-lez v5, :cond_4

    move v5, v4

    goto :goto_3

    :cond_4
    move v5, v3

    :goto_3
    if-eqz p3, :cond_6

    invoke-virtual {p0, v3}, La/e/b/h/d;->u(I)Z

    move-result v7

    if-eqz v7, :cond_6

    iget v7, p0, La/e/b/h/d;->n:I

    if-nez v7, :cond_6

    if-nez v6, :cond_6

    iput-object v1, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    if-eqz v0, :cond_5

    iget p3, p0, La/e/b/h/d;->o:I

    if-nez p3, :cond_5

    iput-object v2, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    :cond_5
    move p3, v3

    :cond_6
    if-eqz v0, :cond_8

    invoke-virtual {p0, v4}, La/e/b/h/d;->u(I)Z

    move-result v7

    if-eqz v7, :cond_8

    iget v7, p0, La/e/b/h/d;->o:I

    if-nez v7, :cond_8

    if-nez v5, :cond_8

    iput-object v1, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    if-eqz p3, :cond_7

    iget v0, p0, La/e/b/h/d;->n:I

    if-nez v0, :cond_7

    iput-object v2, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    :cond_7
    move v0, v3

    :cond_8
    invoke-virtual {p0}, La/e/b/h/d;->z()Z

    move-result v7

    if-eqz v7, :cond_9

    iput-object v2, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    move p3, v3

    :cond_9
    invoke-virtual {p0}, La/e/b/h/d;->A()Z

    move-result v7

    if-eqz v7, :cond_a

    iput-object v2, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    move v0, v3

    :cond_a
    const/4 v7, -0x1

    const/4 v8, 0x4

    if-eqz v6, :cond_f

    iget-object v6, p0, La/e/b/h/d;->p:[I

    aget v6, v6, v3

    if-ne v6, v8, :cond_b

    iput-object v2, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    goto :goto_7

    :cond_b
    if-nez v0, :cond_f

    iget-object v0, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    if-ne v0, v2, :cond_c

    iget v0, p2, La/e/b/h/l/b$a;->d:I

    goto :goto_4

    :cond_c
    iput-object v1, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    move-object v0, p1

    check-cast v0, Landroidx/constraintlayout/widget/ConstraintLayout$b;

    invoke-virtual {v0, p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->b(La/e/b/h/d;La/e/b/h/l/b$a;)V

    iget v0, p2, La/e/b/h/l/b$a;->f:I

    :goto_4
    iput-object v2, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    iget v6, p0, La/e/b/h/d;->V:I

    if-eqz v6, :cond_e

    if-ne v6, v7, :cond_d

    goto :goto_5

    .line 1
    :cond_d
    iget v6, p0, La/e/b/h/d;->U:F

    int-to-float v0, v0

    div-float/2addr v6, v0

    goto :goto_6

    :cond_e
    :goto_5
    iget v6, p0, La/e/b/h/d;->U:F

    int-to-float v0, v0

    mul-float/2addr v6, v0

    :goto_6
    float-to-int v0, v6

    .line 2
    iput v0, p2, La/e/b/h/l/b$a;->c:I

    :cond_f
    :goto_7
    if-eqz v5, :cond_14

    iget-object v0, p0, La/e/b/h/d;->p:[I

    aget v0, v0, v4

    if-ne v0, v8, :cond_10

    iput-object v2, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    goto :goto_b

    :cond_10
    if-nez p3, :cond_14

    iget-object p3, p2, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    if-ne p3, v2, :cond_11

    iget p3, p2, La/e/b/h/l/b$a;->c:I

    goto :goto_8

    :cond_11
    iput-object v1, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    move-object p3, p1

    check-cast p3, Landroidx/constraintlayout/widget/ConstraintLayout$b;

    invoke-virtual {p3, p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->b(La/e/b/h/d;La/e/b/h/l/b$a;)V

    iget p3, p2, La/e/b/h/l/b$a;->e:I

    :goto_8
    iput-object v2, p2, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    iget v0, p0, La/e/b/h/d;->V:I

    if-eqz v0, :cond_13

    if-ne v0, v7, :cond_12

    goto :goto_9

    :cond_12
    int-to-float p3, p3

    .line 3
    iget v0, p0, La/e/b/h/d;->U:F

    mul-float/2addr p3, v0

    goto :goto_a

    :cond_13
    :goto_9
    int-to-float p3, p3

    iget v0, p0, La/e/b/h/d;->U:F

    div-float/2addr p3, v0

    :goto_a
    float-to-int p3, p3

    .line 4
    iput p3, p2, La/e/b/h/l/b$a;->d:I

    :cond_14
    :goto_b
    check-cast p1, Landroidx/constraintlayout/widget/ConstraintLayout$b;

    invoke-virtual {p1, p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->b(La/e/b/h/d;La/e/b/h/l/b$a;)V

    iget p1, p2, La/e/b/h/l/b$a;->e:I

    invoke-virtual {p0, p1}, La/e/b/h/d;->M(I)V

    iget p1, p2, La/e/b/h/l/b$a;->f:I

    invoke-virtual {p0, p1}, La/e/b/h/d;->H(I)V

    iget-boolean p1, p2, La/e/b/h/l/b$a;->h:Z

    .line 5
    iput-boolean p1, p0, La/e/b/h/d;->A:Z

    .line 6
    iget p1, p2, La/e/b/h/l/b$a;->g:I

    invoke-virtual {p0, p1}, La/e/b/h/d;->E(I)V

    iput v3, p2, La/e/b/h/l/b$a;->j:I

    iget-boolean p0, p2, La/e/b/h/l/b$a;->i:Z

    return p0
.end method


# virtual methods
.method public B()V
    .locals 1

    iget-object v0, p0, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v0}, La/e/b/d;->u()V

    const/4 v0, 0x0

    iput v0, p0, La/e/b/h/e;->u0:I

    iput v0, p0, La/e/b/h/e;->v0:I

    invoke-super {p0}, La/e/b/h/k;->B()V

    return-void
.end method

.method public N(ZZ)V
    .locals 3

    invoke-super {p0, p1, p2}, La/e/b/h/d;->N(ZZ)V

    iget-object v0, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    iget-object v2, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/d;

    invoke-virtual {v2, p1, p2}, La/e/b/h/d;->N(ZZ)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public P()V
    .locals 28

    move-object/from16 v1, p0

    sget-object v0, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v3, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    const/4 v4, 0x0

    iput v4, v1, La/e/b/h/d;->W:I

    iput v4, v1, La/e/b/h/d;->X:I

    iput-boolean v4, v1, La/e/b/h/e;->B0:Z

    iput-boolean v4, v1, La/e/b/h/e;->C0:Z

    iget-object v5, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v5

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v6

    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    move-result v6

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v7

    invoke-static {v4, v7}, Ljava/lang/Math;->max(II)I

    move-result v7

    iget-object v8, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v9, 0x1

    aget-object v10, v8, v9

    aget-object v8, v8, v4

    iget v11, v1, La/e/b/h/e;->A0:I

    invoke-static {v11, v9}, La/e/b/h/i;->b(II)Z

    move-result v11

    if-eqz v11, :cond_1c

    .line 1
    iget-object v11, v1, La/e/b/h/e;->r0:La/e/b/h/l/b$b;

    .line 2
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v12

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v13

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->C()V

    .line 3
    iget-object v14, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    .line 4
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    move-result v15

    move v9, v4

    :goto_0
    if-ge v9, v15, :cond_0

    invoke-virtual {v14, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v16

    check-cast v16, La/e/b/h/d;

    invoke-virtual/range {v16 .. v16}, La/e/b/h/d;->C()V

    add-int/lit8 v9, v9, 0x1

    goto :goto_0

    .line 5
    :cond_0
    iget-boolean v9, v1, La/e/b/h/e;->s0:Z

    if-ne v12, v2, :cond_1

    .line 6
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v12

    invoke-virtual {v1, v4, v12}, La/e/b/h/d;->F(II)V

    move/from16 v16, v7

    goto :goto_1

    .line 7
    :cond_1
    iget-object v12, v1, La/e/b/h/d;->F:La/e/b/h/c;

    .line 8
    iput v4, v12, La/e/b/h/c;->b:I

    move/from16 v16, v7

    const/4 v7, 0x1

    iput-boolean v7, v12, La/e/b/h/c;->c:Z

    .line 9
    iput v4, v1, La/e/b/h/d;->W:I

    :goto_1
    move v7, v4

    move v12, v7

    move/from16 v17, v12

    :goto_2
    const/high16 v18, 0x3f000000    # 0.5f

    if-ge v12, v15, :cond_7

    .line 10
    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v19

    move-object/from16 v4, v19

    check-cast v4, La/e/b/h/d;

    move/from16 v19, v6

    instance-of v6, v4, La/e/b/h/f;

    if-eqz v6, :cond_5

    check-cast v4, La/e/b/h/f;

    .line 11
    iget v6, v4, La/e/b/h/f;->s0:I

    move-object/from16 v21, v10

    const/4 v10, 0x1

    if-ne v6, v10, :cond_6

    .line 12
    iget v6, v4, La/e/b/h/f;->p0:I

    const/4 v7, -0x1

    if-eq v6, v7, :cond_2

    goto :goto_3

    .line 13
    :cond_2
    iget v6, v4, La/e/b/h/f;->q0:I

    if-eq v6, v7, :cond_3

    .line 14
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->z()Z

    move-result v6

    if-eqz v6, :cond_3

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v6

    .line 15
    iget v7, v4, La/e/b/h/f;->q0:I

    sub-int/2addr v6, v7

    goto :goto_3

    .line 16
    :cond_3
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->z()Z

    move-result v6

    if-eqz v6, :cond_4

    .line 17
    iget v6, v4, La/e/b/h/f;->o0:F

    .line 18
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v7

    int-to-float v7, v7

    mul-float/2addr v6, v7

    add-float v6, v6, v18

    float-to-int v6, v6

    :goto_3
    invoke-virtual {v4, v6}, La/e/b/h/f;->P(I)V

    :cond_4
    const/4 v7, 0x1

    goto :goto_4

    :cond_5
    move-object/from16 v21, v10

    instance-of v6, v4, La/e/b/h/a;

    if-eqz v6, :cond_6

    check-cast v4, La/e/b/h/a;

    invoke-virtual {v4}, La/e/b/h/a;->R()I

    move-result v4

    if-nez v4, :cond_6

    const/16 v17, 0x1

    :cond_6
    :goto_4
    add-int/lit8 v12, v12, 0x1

    move/from16 v6, v19

    move-object/from16 v10, v21

    const/4 v4, 0x0

    goto :goto_2

    :cond_7
    move/from16 v19, v6

    move-object/from16 v21, v10

    if-eqz v7, :cond_9

    const/4 v4, 0x0

    :goto_5
    if-ge v4, v15, :cond_9

    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    instance-of v7, v6, La/e/b/h/f;

    if-eqz v7, :cond_8

    check-cast v6, La/e/b/h/f;

    .line 19
    iget v7, v6, La/e/b/h/f;->s0:I

    const/4 v10, 0x1

    if-ne v7, v10, :cond_8

    .line 20
    invoke-static {v6, v11, v9}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    :cond_8
    add-int/lit8 v4, v4, 0x1

    goto :goto_5

    :cond_9
    invoke-static {v1, v11, v9}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    if-eqz v17, :cond_b

    const/4 v4, 0x0

    :goto_6
    if-ge v4, v15, :cond_b

    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    instance-of v7, v6, La/e/b/h/a;

    if-eqz v7, :cond_a

    check-cast v6, La/e/b/h/a;

    invoke-virtual {v6}, La/e/b/h/a;->R()I

    move-result v7

    if-nez v7, :cond_a

    .line 21
    invoke-virtual {v6}, La/e/b/h/a;->Q()Z

    move-result v7

    if-eqz v7, :cond_a

    invoke-static {v6, v11, v9}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    :cond_a
    add-int/lit8 v4, v4, 0x1

    goto :goto_6

    :cond_b
    if-ne v13, v2, :cond_c

    .line 22
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v4

    const/4 v6, 0x0

    invoke-virtual {v1, v6, v4}, La/e/b/h/d;->G(II)V

    goto :goto_7

    :cond_c
    const/4 v6, 0x0

    .line 23
    iget-object v4, v1, La/e/b/h/d;->G:La/e/b/h/c;

    .line 24
    iput v6, v4, La/e/b/h/c;->b:I

    const/4 v7, 0x1

    iput-boolean v7, v4, La/e/b/h/c;->c:Z

    .line 25
    iput v6, v1, La/e/b/h/d;->X:I

    :goto_7
    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    :goto_8
    if-ge v7, v15, :cond_13

    .line 26
    invoke-virtual {v14, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, La/e/b/h/d;

    instance-of v12, v10, La/e/b/h/f;

    if-eqz v12, :cond_11

    check-cast v10, La/e/b/h/f;

    .line 27
    iget v12, v10, La/e/b/h/f;->s0:I

    if-nez v12, :cond_10

    .line 28
    iget v4, v10, La/e/b/h/f;->p0:I

    const/4 v12, -0x1

    if-eq v4, v12, :cond_d

    goto :goto_9

    .line 29
    :cond_d
    iget v4, v10, La/e/b/h/f;->q0:I

    if-eq v4, v12, :cond_e

    .line 30
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->A()Z

    move-result v4

    if-eqz v4, :cond_e

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v4

    .line 31
    iget v13, v10, La/e/b/h/f;->q0:I

    sub-int/2addr v4, v13

    goto :goto_9

    .line 32
    :cond_e
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->A()Z

    move-result v4

    if-eqz v4, :cond_f

    .line 33
    iget v4, v10, La/e/b/h/f;->o0:F

    .line 34
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v13

    int-to-float v13, v13

    mul-float/2addr v4, v13

    add-float v4, v4, v18

    float-to-int v4, v4

    :goto_9
    invoke-virtual {v10, v4}, La/e/b/h/f;->P(I)V

    :cond_f
    const/4 v4, 0x1

    goto :goto_a

    :cond_10
    const/4 v12, -0x1

    goto :goto_a

    :cond_11
    const/4 v12, -0x1

    instance-of v13, v10, La/e/b/h/a;

    if-eqz v13, :cond_12

    check-cast v10, La/e/b/h/a;

    invoke-virtual {v10}, La/e/b/h/a;->R()I

    move-result v10

    const/4 v13, 0x1

    if-ne v10, v13, :cond_12

    const/4 v6, 0x1

    :cond_12
    :goto_a
    add-int/lit8 v7, v7, 0x1

    goto :goto_8

    :cond_13
    if-eqz v4, :cond_15

    const/4 v4, 0x0

    :goto_b
    if-ge v4, v15, :cond_15

    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, La/e/b/h/d;

    instance-of v10, v7, La/e/b/h/f;

    if-eqz v10, :cond_14

    check-cast v7, La/e/b/h/f;

    .line 35
    iget v10, v7, La/e/b/h/f;->s0:I

    if-nez v10, :cond_14

    .line 36
    invoke-static {v7, v11}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    :cond_14
    add-int/lit8 v4, v4, 0x1

    goto :goto_b

    :cond_15
    invoke-static {v1, v11}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    if-eqz v6, :cond_17

    const/4 v4, 0x0

    :goto_c
    if-ge v4, v15, :cond_17

    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    instance-of v7, v6, La/e/b/h/a;

    if-eqz v7, :cond_16

    check-cast v6, La/e/b/h/a;

    invoke-virtual {v6}, La/e/b/h/a;->R()I

    move-result v7

    const/4 v10, 0x1

    if-ne v7, v10, :cond_16

    .line 37
    invoke-virtual {v6}, La/e/b/h/a;->Q()Z

    move-result v7

    if-eqz v7, :cond_16

    invoke-static {v6, v11}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    :cond_16
    add-int/lit8 v4, v4, 0x1

    goto :goto_c

    :cond_17
    const/4 v4, 0x0

    :goto_d
    if-ge v4, v15, :cond_19

    .line 38
    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    invoke-virtual {v6}, La/e/b/h/d;->y()Z

    move-result v7

    if-eqz v7, :cond_18

    invoke-static {v6}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v7

    if-eqz v7, :cond_18

    sget-object v7, La/e/b/h/l/h;->a:La/e/b/h/l/b$a;

    const/4 v10, 0x0

    invoke-static {v6, v11, v7, v10}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    invoke-static {v6, v11, v9}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    invoke-static {v6, v11}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    :cond_18
    add-int/lit8 v4, v4, 0x1

    goto :goto_d

    :cond_19
    const/4 v4, 0x0

    :goto_e
    if-ge v4, v5, :cond_1d

    .line 39
    iget-object v6, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    invoke-virtual {v6}, La/e/b/h/d;->y()Z

    move-result v7

    if-eqz v7, :cond_1b

    instance-of v7, v6, La/e/b/h/f;

    if-nez v7, :cond_1b

    instance-of v7, v6, La/e/b/h/a;

    if-nez v7, :cond_1b

    instance-of v7, v6, La/e/b/h/j;

    if-nez v7, :cond_1b

    .line 40
    iget-boolean v7, v6, La/e/b/h/d;->C:Z

    if-nez v7, :cond_1b

    const/4 v7, 0x0

    .line 41
    invoke-virtual {v6, v7}, La/e/b/h/d;->k(I)La/e/b/h/d$a;

    move-result-object v9

    const/4 v7, 0x1

    invoke-virtual {v6, v7}, La/e/b/h/d;->k(I)La/e/b/h/d$a;

    move-result-object v10

    if-ne v9, v0, :cond_1a

    iget v9, v6, La/e/b/h/d;->n:I

    if-eq v9, v7, :cond_1a

    if-ne v10, v0, :cond_1a

    iget v9, v6, La/e/b/h/d;->o:I

    if-eq v9, v7, :cond_1a

    const/4 v7, 0x1

    goto :goto_f

    :cond_1a
    const/4 v7, 0x0

    :goto_f
    if-nez v7, :cond_1b

    new-instance v7, La/e/b/h/l/b$a;

    invoke-direct {v7}, La/e/b/h/l/b$a;-><init>()V

    iget-object v9, v1, La/e/b/h/e;->r0:La/e/b/h/l/b$b;

    const/4 v10, 0x0

    invoke-static {v6, v9, v7, v10}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_1b
    add-int/lit8 v4, v4, 0x1

    goto :goto_e

    :cond_1c
    move/from16 v19, v6

    move/from16 v16, v7

    move-object/from16 v21, v10

    :cond_1d
    const/4 v4, 0x2

    if-le v5, v4, :cond_52

    move-object/from16 v7, v21

    if-eq v8, v3, :cond_1e

    if-ne v7, v3, :cond_51

    :cond_1e
    iget v9, v1, La/e/b/h/e;->A0:I

    const/16 v10, 0x400

    invoke-static {v9, v10}, La/e/b/h/i;->b(II)Z

    move-result v9

    if-eqz v9, :cond_51

    .line 42
    iget-object v9, v1, La/e/b/h/e;->r0:La/e/b/h/l/b$b;

    .line 43
    sget-object v10, La/e/b/h/c$a;->h:La/e/b/h/c$a;

    iget-object v11, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    .line 44
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    move-result v12

    const/4 v13, 0x0

    :goto_10
    if-ge v13, v12, :cond_20

    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, La/e/b/h/d;

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v15

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v4

    invoke-virtual {v14}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v6

    invoke-virtual {v14}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v14

    invoke-static {v15, v4, v6, v14}, La/b/k/h$i;->E(La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;)Z

    move-result v4

    if-nez v4, :cond_1f

    move-object/from16 v24, v2

    move-object v4, v3

    move/from16 v21, v5

    move-object/from16 v23, v7

    move-object/from16 v22, v8

    goto/16 :goto_27

    :cond_1f
    add-int/lit8 v13, v13, 0x1

    const/4 v4, 0x2

    goto :goto_10

    :cond_20
    move/from16 v21, v5

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v20, 0x0

    :goto_11
    if-ge v5, v12, :cond_30

    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v22

    move-object/from16 v23, v7

    move-object/from16 v7, v22

    check-cast v7, La/e/b/h/d;

    move-object/from16 v22, v8

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v8

    move-object/from16 v24, v2

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v2

    move-object/from16 v25, v3

    invoke-virtual {v7}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v3

    move-object/from16 v26, v0

    invoke-virtual {v7}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v0

    invoke-static {v8, v2, v3, v0}, La/b/k/h$i;->E(La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;)Z

    move-result v0

    if-nez v0, :cond_21

    iget-object v0, v1, La/e/b/h/e;->H0:La/e/b/h/l/b$a;

    const/4 v2, 0x0

    invoke-static {v7, v9, v0, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_21
    instance-of v0, v7, La/e/b/h/f;

    if-eqz v0, :cond_25

    move-object v2, v7

    check-cast v2, La/e/b/h/f;

    .line 45
    iget v3, v2, La/e/b/h/f;->s0:I

    if-nez v3, :cond_23

    if-nez v13, :cond_22

    .line 46
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    move-object v13, v3

    :cond_22
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    :cond_23
    iget v3, v2, La/e/b/h/f;->s0:I

    const/4 v8, 0x1

    if-ne v3, v8, :cond_25

    if-nez v4, :cond_24

    .line 48
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    :cond_24
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_25
    instance-of v2, v7, La/e/b/h/h;

    if-eqz v2, :cond_2b

    instance-of v2, v7, La/e/b/h/a;

    if-eqz v2, :cond_28

    move-object v2, v7

    check-cast v2, La/e/b/h/a;

    invoke-virtual {v2}, La/e/b/h/a;->R()I

    move-result v3

    if-nez v3, :cond_27

    if-nez v6, :cond_26

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    move-object v6, v3

    :cond_26
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_27
    invoke-virtual {v2}, La/e/b/h/a;->R()I

    move-result v3

    const/4 v8, 0x1

    if-ne v3, v8, :cond_2b

    if-nez v14, :cond_2a

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    goto :goto_12

    :cond_28
    move-object v2, v7

    check-cast v2, La/e/b/h/h;

    if-nez v6, :cond_29

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    :cond_29
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-nez v14, :cond_2a

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    :goto_12
    move-object v14, v3

    :cond_2a
    invoke-virtual {v14, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2b
    iget-object v2, v7, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_2d

    iget-object v2, v7, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_2d

    if-nez v0, :cond_2d

    instance-of v2, v7, La/e/b/h/a;

    if-nez v2, :cond_2d

    if-nez v15, :cond_2c

    new-instance v15, Ljava/util/ArrayList;

    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    :cond_2c
    invoke-virtual {v15, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2d
    iget-object v2, v7, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_2f

    iget-object v2, v7, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_2f

    iget-object v2, v7, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_2f

    if-nez v0, :cond_2f

    instance-of v0, v7, La/e/b/h/a;

    if-nez v0, :cond_2f

    if-nez v20, :cond_2e

    new-instance v20, Ljava/util/ArrayList;

    invoke-direct/range {v20 .. v20}, Ljava/util/ArrayList;-><init>()V

    :cond_2e
    move-object/from16 v0, v20

    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v20, v0

    :cond_2f
    add-int/lit8 v5, v5, 0x1

    move-object/from16 v8, v22

    move-object/from16 v7, v23

    move-object/from16 v2, v24

    move-object/from16 v3, v25

    move-object/from16 v0, v26

    goto/16 :goto_11

    :cond_30
    move-object/from16 v26, v0

    move-object/from16 v24, v2

    move-object/from16 v25, v3

    move-object/from16 v23, v7

    move-object/from16 v22, v8

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    if-eqz v4, :cond_31

    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_13
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_31

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/f;

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_13

    :cond_31
    const/4 v4, 0x0

    const/4 v5, 0x0

    if-eqz v6, :cond_32

    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_14
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_32

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/h;

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    move-result-object v6

    invoke-virtual {v3, v0, v5, v6}, La/e/b/h/h;->P(Ljava/util/ArrayList;ILa/e/b/h/l/n;)V

    invoke-virtual {v6, v0}, La/e/b/h/l/n;->b(Ljava/util/ArrayList;)V

    const/4 v4, 0x0

    const/4 v5, 0x0

    goto :goto_14

    :cond_32
    sget-object v2, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-virtual {v1, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 49
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_33

    .line 50
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_15
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_33

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_15

    :cond_33
    sget-object v2, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    invoke-virtual {v1, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 51
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_34

    .line 52
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_16
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_34

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_16

    :cond_34
    invoke-virtual {v1, v10}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 53
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_35

    .line 54
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_17
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_35

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_17

    :cond_35
    const/4 v4, 0x0

    const/4 v5, 0x0

    if-eqz v15, :cond_36

    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_18
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_36

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_18

    :cond_36
    if-eqz v13, :cond_37

    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_19
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_37

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/f;

    const/4 v5, 0x1

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_19

    :cond_37
    const/4 v5, 0x1

    if-eqz v14, :cond_38

    invoke-virtual {v14}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1a
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_38

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/h;

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    move-result-object v6

    invoke-virtual {v3, v0, v5, v6}, La/e/b/h/h;->P(Ljava/util/ArrayList;ILa/e/b/h/l/n;)V

    invoke-virtual {v6, v0}, La/e/b/h/l/n;->b(Ljava/util/ArrayList;)V

    const/4 v4, 0x0

    const/4 v5, 0x1

    goto :goto_1a

    :cond_38
    sget-object v2, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    invoke-virtual {v1, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 55
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_39

    .line 56
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_39

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x1

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_1b

    :cond_39
    sget-object v2, La/e/b/h/c$a;->g:La/e/b/h/c$a;

    invoke-virtual {v1, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 57
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_3a

    .line 58
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1c
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3a

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x1

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_1c

    :cond_3a
    sget-object v2, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    invoke-virtual {v1, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 59
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_3b

    .line 60
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1d
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x1

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_1d

    :cond_3b
    invoke-virtual {v1, v10}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    .line 61
    iget-object v2, v2, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v2, :cond_3c

    .line 62
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3c

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v4, 0x0

    const/4 v5, 0x1

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_1e

    :cond_3c
    const/4 v4, 0x0

    const/4 v5, 0x1

    if-eqz v20, :cond_3d

    invoke-virtual/range {v20 .. v20}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3d

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    invoke-static {v3, v5, v0, v4}, La/b/k/h$i;->h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;

    goto :goto_1f

    :cond_3d
    const/4 v2, 0x0

    :goto_20
    if-ge v2, v12, :cond_40

    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    .line 63
    iget-object v4, v3, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v6, 0x0

    aget-object v7, v4, v6

    move-object/from16 v6, v26

    if-ne v7, v6, :cond_3e

    aget-object v4, v4, v5

    if-ne v4, v6, :cond_3e

    const/4 v4, 0x1

    goto :goto_21

    :cond_3e
    const/4 v4, 0x0

    :goto_21
    if-eqz v4, :cond_3f

    .line 64
    iget v4, v3, La/e/b/h/d;->m0:I

    invoke-static {v0, v4}, La/b/k/h$i;->i(Ljava/util/ArrayList;I)La/e/b/h/l/n;

    move-result-object v4

    iget v3, v3, La/e/b/h/d;->n0:I

    invoke-static {v0, v3}, La/b/k/h$i;->i(Ljava/util/ArrayList;I)La/e/b/h/l/n;

    move-result-object v3

    if-eqz v4, :cond_3f

    if-eqz v3, :cond_3f

    const/4 v5, 0x0

    invoke-virtual {v4, v5, v3}, La/e/b/h/l/n;->d(ILa/e/b/h/l/n;)V

    const/4 v5, 0x2

    .line 65
    iput v5, v3, La/e/b/h/l/n;->c:I

    .line 66
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_3f
    add-int/lit8 v2, v2, 0x1

    move-object/from16 v26, v6

    const/4 v5, 0x1

    goto :goto_20

    :cond_40
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x1

    if-gt v2, v3, :cond_41

    move-object/from16 v4, v25

    goto/16 :goto_27

    :cond_41
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v2

    move-object/from16 v4, v25

    if-ne v2, v4, :cond_45

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    const/4 v5, 0x0

    const/4 v6, 0x0

    :goto_22
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_44

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, La/e/b/h/l/n;

    .line 67
    iget v8, v7, La/e/b/h/l/n;->c:I

    if-ne v8, v3, :cond_42

    const/4 v8, 0x0

    goto :goto_23

    .line 68
    :cond_42
    iget-object v3, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v8, 0x0

    .line 69
    invoke-virtual {v7, v3, v8}, La/e/b/h/l/n;->c(La/e/b/d;I)I

    move-result v3

    if-le v3, v6, :cond_43

    move v6, v3

    move-object v5, v7

    :cond_43
    :goto_23
    const/4 v3, 0x1

    goto :goto_22

    :cond_44
    const/4 v8, 0x0

    if-eqz v5, :cond_45

    .line 70
    iget-object v2, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v24, v2, v8

    .line 71
    invoke-virtual {v1, v6}, La/e/b/h/d;->M(I)V

    goto :goto_24

    :cond_45
    const/4 v5, 0x0

    :goto_24
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v2

    if-ne v2, v4, :cond_49

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v2, 0x0

    const/4 v3, 0x0

    :cond_46
    :goto_25
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_48

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/l/n;

    .line 72
    iget v7, v6, La/e/b/h/l/n;->c:I

    if-nez v7, :cond_47

    const/4 v8, 0x1

    goto :goto_25

    .line 73
    :cond_47
    iget-object v7, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v8, 0x1

    .line 74
    invoke-virtual {v6, v7, v8}, La/e/b/h/l/n;->c(La/e/b/d;I)I

    move-result v7

    if-le v7, v3, :cond_46

    move-object v2, v6

    move v3, v7

    goto :goto_25

    :cond_48
    const/4 v8, 0x1

    if-eqz v2, :cond_49

    .line 75
    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v24, v0, v8

    .line 76
    invoke-virtual {v1, v3}, La/e/b/h/d;->H(I)V

    goto :goto_26

    :cond_49
    const/4 v2, 0x0

    :goto_26
    if-nez v5, :cond_4b

    if-eqz v2, :cond_4a

    goto :goto_28

    :cond_4a
    :goto_27
    const/4 v0, 0x0

    goto :goto_29

    :cond_4b
    :goto_28
    const/4 v0, 0x1

    :goto_29
    if-eqz v0, :cond_50

    move-object/from16 v2, v22

    if-ne v2, v4, :cond_4d

    .line 77
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v0

    move/from16 v3, v19

    if-ge v3, v0, :cond_4c

    if-lez v3, :cond_4c

    invoke-virtual {v1, v3}, La/e/b/h/d;->M(I)V

    const/4 v5, 0x1

    iput-boolean v5, v1, La/e/b/h/e;->B0:Z

    goto :goto_2a

    :cond_4c
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v6

    goto :goto_2b

    :cond_4d
    move/from16 v3, v19

    :goto_2a
    move v6, v3

    :goto_2b
    move-object/from16 v5, v23

    if-ne v5, v4, :cond_4f

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v0

    move/from16 v7, v16

    if-ge v7, v0, :cond_4e

    if-lez v7, :cond_4e

    invoke-virtual {v1, v7}, La/e/b/h/d;->H(I)V

    const/4 v3, 0x1

    iput-boolean v3, v1, La/e/b/h/e;->C0:Z

    goto :goto_2c

    :cond_4e
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v7

    goto :goto_2c

    :cond_4f
    move/from16 v7, v16

    :goto_2c
    const/4 v0, 0x1

    goto :goto_2e

    :cond_50
    move/from16 v7, v16

    move/from16 v3, v19

    move-object/from16 v2, v22

    move-object/from16 v5, v23

    goto :goto_2d

    :cond_51
    move-object/from16 v24, v2

    move-object v4, v3

    move/from16 v21, v5

    move-object v5, v7

    move-object v2, v8

    move/from16 v7, v16

    move/from16 v3, v19

    goto :goto_2d

    :cond_52
    move-object/from16 v24, v2

    move-object v4, v3

    move-object v2, v8

    move/from16 v7, v16

    move/from16 v3, v19

    move-object/from16 v27, v21

    move/from16 v21, v5

    move-object/from16 v5, v27

    :goto_2d
    move v6, v3

    const/4 v0, 0x0

    :goto_2e
    const/16 v3, 0x40

    invoke-virtual {v1, v3}, La/e/b/h/e;->Y(I)Z

    move-result v8

    if-nez v8, :cond_54

    const/16 v8, 0x80

    invoke-virtual {v1, v8}, La/e/b/h/e;->Y(I)Z

    move-result v8

    if-eqz v8, :cond_53

    goto :goto_2f

    :cond_53
    const/4 v8, 0x0

    goto :goto_30

    :cond_54
    :goto_2f
    const/4 v8, 0x1

    :goto_30
    iget-object v9, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v10, 0x0

    iput-boolean v10, v9, La/e/b/d;->h:Z

    iput-boolean v10, v9, La/e/b/d;->i:Z

    iget v10, v1, La/e/b/h/e;->A0:I

    if-eqz v10, :cond_55

    if-eqz v8, :cond_55

    const/4 v8, 0x1

    iput-boolean v8, v9, La/e/b/d;->i:Z

    :cond_55
    iget-object v8, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v9

    if-eq v9, v4, :cond_57

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v9

    if-ne v9, v4, :cond_56

    goto :goto_31

    :cond_56
    const/4 v9, 0x0

    goto :goto_32

    :cond_57
    :goto_31
    const/4 v9, 0x1

    :goto_32
    const/4 v10, 0x0

    .line 78
    iput v10, v1, La/e/b/h/e;->w0:I

    iput v10, v1, La/e/b/h/e;->x0:I

    move/from16 v11, v21

    const/4 v10, 0x0

    :goto_33
    if-ge v10, v11, :cond_59

    .line 79
    iget-object v12, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v12, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, La/e/b/h/d;

    instance-of v13, v12, La/e/b/h/k;

    if-eqz v13, :cond_58

    check-cast v12, La/e/b/h/k;

    invoke-virtual {v12}, La/e/b/h/k;->P()V

    :cond_58
    add-int/lit8 v10, v10, 0x1

    goto :goto_33

    :cond_59
    invoke-virtual {v1, v3}, La/e/b/h/e;->Y(I)Z

    move-result v10

    move v12, v0

    const/4 v0, 0x0

    const/4 v13, 0x1

    :goto_34
    if-eqz v13, :cond_69

    const/4 v14, 0x1

    add-int/lit8 v15, v0, 0x1

    :try_start_0
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v0}, La/e/b/d;->u()V

    const/4 v14, 0x0

    .line 80
    iput v14, v1, La/e/b/h/e;->w0:I

    iput v14, v1, La/e/b/h/e;->x0:I

    .line 81
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v1, v0}, La/e/b/h/d;->g(La/e/b/d;)V

    const/4 v0, 0x0

    :goto_35
    if-ge v0, v11, :cond_5a

    iget-object v14, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v14, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, La/e/b/h/d;

    iget-object v3, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v14, v3}, La/e/b/h/d;->g(La/e/b/d;)V

    add-int/lit8 v0, v0, 0x1

    const/16 v3, 0x40

    goto :goto_35

    :cond_5a
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v1, v0}, La/e/b/h/e;->R(La/e/b/d;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_3

    :try_start_1
    iget-object v0, v1, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    const/4 v3, 0x5

    if-eqz v0, :cond_5b

    iget-object v0, v1, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_5b

    iget-object v0, v1, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    iget-object v14, v1, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v13, v14}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v13

    .line 82
    iget-object v14, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget-object v14, v1, La/e/b/h/e;->t0:La/e/b/d;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_2

    move/from16 v19, v12

    const/4 v12, 0x0

    :try_start_2
    invoke-virtual {v14, v0, v13, v12, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    const/4 v12, 0x0

    .line 83
    iput-object v12, v1, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    goto :goto_36

    :cond_5b
    move/from16 v19, v12

    :goto_36
    iget-object v0, v1, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_5c

    iget-object v0, v1, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_5c

    iget-object v0, v1, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v12, v1, La/e/b/h/e;->t0:La/e/b/d;

    iget-object v13, v1, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v12, v13}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v12

    .line 84
    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v13, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v14, 0x0

    invoke-virtual {v13, v12, v0, v14, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    const/4 v12, 0x0

    .line 85
    iput-object v12, v1, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    :cond_5c
    iget-object v0, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_5d

    iget-object v0, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_5d

    iget-object v0, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v12, v1, La/e/b/h/e;->t0:La/e/b/d;

    iget-object v13, v1, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v12, v13}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v12

    .line 86
    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v13, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v14, 0x0

    invoke-virtual {v13, v0, v12, v14, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    const/4 v12, 0x0

    .line 87
    iput-object v12, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    goto :goto_38

    :goto_37
    const/4 v3, 0x0

    goto :goto_3a

    :cond_5d
    :goto_38
    iget-object v0, v1, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_5e

    iget-object v0, v1, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_5e

    iget-object v0, v1, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v12, v1, La/e/b/h/e;->t0:La/e/b/d;

    iget-object v13, v1, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v12, v13}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v12

    .line 88
    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v13, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget-object v13, v1, La/e/b/h/e;->t0:La/e/b/d;

    const/4 v14, 0x0

    invoke-virtual {v13, v12, v0, v14, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    const/4 v3, 0x0

    .line 89
    :try_start_3
    iput-object v3, v1, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    goto :goto_39

    :catch_0
    move-exception v0

    goto :goto_37

    :cond_5e
    const/4 v3, 0x0

    :goto_39
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v0}, La/e/b/d;->q()V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    const/4 v13, 0x1

    goto :goto_3c

    :catch_1
    move-exception v0

    goto :goto_3a

    :catch_2
    move-exception v0

    move/from16 v19, v12

    goto :goto_37

    :goto_3a
    const/4 v13, 0x1

    goto :goto_3b

    :catch_3
    move-exception v0

    move/from16 v19, v12

    const/4 v3, 0x0

    :goto_3b
    invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V

    sget-object v12, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v14, Ljava/lang/StringBuilder;

    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "EXCEPTION : "

    invoke-virtual {v14, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v14, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v12, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    :goto_3c
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    if-eqz v13, :cond_5f

    sget-object v3, La/e/b/h/i;->a:[Z

    const/4 v12, 0x2

    const/4 v13, 0x0

    .line 90
    aput-boolean v13, v3, v12

    const/16 v3, 0x40

    invoke-virtual {v1, v3}, La/e/b/h/e;->Y(I)Z

    move-result v12

    invoke-virtual {v1, v0, v12}, La/e/b/h/d;->O(La/e/b/d;Z)V

    iget-object v13, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    move-result v13

    const/4 v14, 0x0

    :goto_3d
    if-ge v14, v13, :cond_60

    iget-object v3, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    invoke-virtual {v3, v0, v12}, La/e/b/h/d;->O(La/e/b/d;Z)V

    add-int/lit8 v14, v14, 0x1

    const/16 v3, 0x40

    goto :goto_3d

    .line 91
    :cond_5f
    invoke-virtual {v1, v0, v10}, La/e/b/h/d;->O(La/e/b/d;Z)V

    const/4 v0, 0x0

    :goto_3e
    if-ge v0, v11, :cond_60

    iget-object v3, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    iget-object v12, v1, La/e/b/h/e;->t0:La/e/b/d;

    invoke-virtual {v3, v12, v10}, La/e/b/h/d;->O(La/e/b/d;Z)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_3e

    :cond_60
    if-eqz v9, :cond_63

    const/16 v0, 0x8

    if-ge v15, v0, :cond_63

    sget-object v0, La/e/b/h/i;->a:[Z

    const/4 v3, 0x2

    aget-boolean v0, v0, v3

    if-eqz v0, :cond_63

    const/4 v0, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    :goto_3f
    if-ge v0, v11, :cond_61

    iget-object v14, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v14, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, La/e/b/h/d;

    iget v3, v14, La/e/b/h/d;->W:I

    invoke-virtual {v14}, La/e/b/h/d;->r()I

    move-result v20

    add-int v3, v20, v3

    invoke-static {v12, v3}, Ljava/lang/Math;->max(II)I

    move-result v12

    iget v3, v14, La/e/b/h/d;->X:I

    invoke-virtual {v14}, La/e/b/h/d;->l()I

    move-result v14

    add-int/2addr v14, v3

    invoke-static {v13, v14}, Ljava/lang/Math;->max(II)I

    move-result v13

    add-int/lit8 v0, v0, 0x1

    const/4 v3, 0x2

    goto :goto_3f

    :cond_61
    iget v0, v1, La/e/b/h/d;->Z:I

    invoke-static {v0, v12}, Ljava/lang/Math;->max(II)I

    move-result v0

    iget v3, v1, La/e/b/h/d;->a0:I

    invoke-static {v3, v13}, Ljava/lang/Math;->max(II)I

    move-result v3

    if-ne v2, v4, :cond_62

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v12

    if-ge v12, v0, :cond_62

    invoke-virtual {v1, v0}, La/e/b/h/d;->M(I)V

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v12, 0x0

    aput-object v4, v0, v12

    const/4 v0, 0x1

    const/16 v19, 0x1

    goto :goto_40

    :cond_62
    const/4 v0, 0x0

    :goto_40
    if-ne v5, v4, :cond_64

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v12

    if-ge v12, v3, :cond_64

    invoke-virtual {v1, v3}, La/e/b/h/d;->H(I)V

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x1

    aput-object v4, v0, v3

    const/4 v0, 0x1

    const/16 v19, 0x1

    goto :goto_41

    :cond_63
    const/4 v0, 0x0

    :cond_64
    :goto_41
    iget v3, v1, La/e/b/h/d;->Z:I

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v12

    invoke-static {v3, v12}, Ljava/lang/Math;->max(II)I

    move-result v3

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v12

    if-le v3, v12, :cond_65

    invoke-virtual {v1, v3}, La/e/b/h/d;->M(I)V

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x0

    aput-object v24, v0, v3

    const/4 v0, 0x1

    const/16 v19, 0x1

    :cond_65
    iget v3, v1, La/e/b/h/d;->a0:I

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v12

    invoke-static {v3, v12}, Ljava/lang/Math;->max(II)I

    move-result v3

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v12

    if-le v3, v12, :cond_66

    invoke-virtual {v1, v3}, La/e/b/h/d;->H(I)V

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x1

    aput-object v24, v0, v3

    move v0, v3

    move/from16 v19, v0

    goto :goto_42

    :cond_66
    const/4 v3, 0x1

    :goto_42
    if-nez v19, :cond_68

    iget-object v12, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v13, 0x0

    aget-object v12, v12, v13

    if-ne v12, v4, :cond_67

    if-lez v6, :cond_67

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->r()I

    move-result v12

    if-le v12, v6, :cond_67

    iput-boolean v3, v1, La/e/b/h/e;->B0:Z

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v24, v0, v13

    invoke-virtual {v1, v6}, La/e/b/h/d;->M(I)V

    move v0, v3

    move/from16 v19, v0

    :cond_67
    iget-object v12, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v12, v12, v3

    if-ne v12, v4, :cond_68

    if-lez v7, :cond_68

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->l()I

    move-result v12

    if-le v12, v7, :cond_68

    iput-boolean v3, v1, La/e/b/h/e;->C0:Z

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v24, v0, v3

    invoke-virtual {v1, v7}, La/e/b/h/d;->H(I)V

    const/4 v12, 0x1

    const/4 v13, 0x1

    goto :goto_43

    :cond_68
    move v13, v0

    move/from16 v12, v19

    :goto_43
    move v0, v15

    const/16 v3, 0x40

    goto/16 :goto_34

    :cond_69
    move/from16 v19, v12

    iput-object v8, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    if-eqz v19, :cond_6a

    iget-object v0, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v3, 0x0

    aput-object v2, v0, v3

    const/4 v2, 0x1

    aput-object v5, v0, v2

    :cond_6a
    iget-object v0, v1, La/e/b/h/e;->t0:La/e/b/d;

    .line 92
    iget-object v0, v0, La/e/b/d;->n:La/e/b/c;

    .line 93
    invoke-virtual {v1, v0}, La/e/b/h/k;->D(La/e/b/c;)V

    return-void
.end method

.method public Q(La/e/b/h/d;I)V
    .locals 5

    const/4 v0, 0x1

    if-nez p2, :cond_1

    .line 1
    iget p2, p0, La/e/b/h/e;->w0:I

    add-int/2addr p2, v0

    iget-object v1, p0, La/e/b/h/e;->z0:[La/e/b/h/b;

    array-length v2, v1

    if-lt p2, v2, :cond_0

    array-length p2, v1

    mul-int/lit8 p2, p2, 0x2

    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [La/e/b/h/b;

    iput-object p2, p0, La/e/b/h/e;->z0:[La/e/b/h/b;

    :cond_0
    iget-object p2, p0, La/e/b/h/e;->z0:[La/e/b/h/b;

    iget v1, p0, La/e/b/h/e;->w0:I

    new-instance v2, La/e/b/h/b;

    const/4 v3, 0x0

    .line 2
    iget-boolean v4, p0, La/e/b/h/e;->s0:Z

    .line 3
    invoke-direct {v2, p1, v3, v4}, La/e/b/h/b;-><init>(La/e/b/h/d;IZ)V

    aput-object v2, p2, v1

    iget p1, p0, La/e/b/h/e;->w0:I

    add-int/2addr p1, v0

    iput p1, p0, La/e/b/h/e;->w0:I

    goto :goto_0

    :cond_1
    if-ne p2, v0, :cond_3

    .line 4
    iget p2, p0, La/e/b/h/e;->x0:I

    add-int/2addr p2, v0

    iget-object v1, p0, La/e/b/h/e;->y0:[La/e/b/h/b;

    array-length v2, v1

    if-lt p2, v2, :cond_2

    array-length p2, v1

    mul-int/lit8 p2, p2, 0x2

    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [La/e/b/h/b;

    iput-object p2, p0, La/e/b/h/e;->y0:[La/e/b/h/b;

    :cond_2
    iget-object p2, p0, La/e/b/h/e;->y0:[La/e/b/h/b;

    iget v1, p0, La/e/b/h/e;->x0:I

    new-instance v2, La/e/b/h/b;

    .line 5
    iget-boolean v3, p0, La/e/b/h/e;->s0:Z

    .line 6
    invoke-direct {v2, p1, v0, v3}, La/e/b/h/b;-><init>(La/e/b/h/d;IZ)V

    aput-object v2, p2, v1

    iget p1, p0, La/e/b/h/e;->x0:I

    add-int/2addr p1, v0

    iput p1, p0, La/e/b/h/e;->x0:I

    :cond_3
    :goto_0
    return-void
.end method

.method public R(La/e/b/d;)Z
    .locals 14

    sget-object v0, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    const/16 v2, 0x40

    invoke-virtual {p0, v2}, La/e/b/h/e;->Y(I)Z

    move-result v2

    invoke-virtual {p0, p1, v2}, La/e/b/h/d;->d(La/e/b/d;Z)V

    iget-object v3, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v3

    const/4 v4, 0x0

    move v5, v4

    move v6, v5

    :goto_0
    const/4 v7, 0x1

    if-ge v5, v3, :cond_1

    iget-object v8, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, La/e/b/h/d;

    .line 1
    iget-object v9, v8, La/e/b/h/d;->P:[Z

    aput-boolean v4, v9, v4

    aput-boolean v4, v9, v7

    .line 2
    instance-of v8, v8, La/e/b/h/a;

    if-eqz v8, :cond_0

    move v6, v7

    :cond_0
    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_1
    if-eqz v6, :cond_7

    move v5, v4

    :goto_1
    if-ge v5, v3, :cond_7

    iget-object v6, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    instance-of v8, v6, La/e/b/h/a;

    if-eqz v8, :cond_6

    check-cast v6, La/e/b/h/a;

    move v8, v4

    .line 3
    :goto_2
    iget v9, v6, La/e/b/h/h;->p0:I

    if-ge v8, v9, :cond_6

    iget-object v9, v6, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v9, v9, v8

    iget v10, v6, La/e/b/h/a;->q0:I

    if-eqz v10, :cond_4

    if-ne v10, v7, :cond_2

    goto :goto_3

    :cond_2
    const/4 v11, 0x2

    if-eq v10, v11, :cond_3

    const/4 v11, 0x3

    if-ne v10, v11, :cond_5

    .line 4
    :cond_3
    iget-object v9, v9, La/e/b/h/d;->P:[Z

    aput-boolean v7, v9, v7

    goto :goto_4

    :cond_4
    :goto_3
    iget-object v9, v9, La/e/b/h/d;->P:[Z

    aput-boolean v7, v9, v4

    :cond_5
    :goto_4
    add-int/lit8 v8, v8, 0x1

    goto :goto_2

    :cond_6
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_7
    move v5, v4

    :goto_5
    if-ge v5, v3, :cond_9

    .line 5
    iget-object v6, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    invoke-virtual {v6}, La/e/b/h/d;->c()Z

    move-result v8

    if-eqz v8, :cond_8

    invoke-virtual {v6, p1, v2}, La/e/b/h/d;->d(La/e/b/d;Z)V

    :cond_8
    add-int/lit8 v5, v5, 0x1

    goto :goto_5

    :cond_9
    sget-boolean v5, La/e/b/d;->r:Z

    if-eqz v5, :cond_d

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    move v5, v4

    :goto_6
    if-ge v5, v3, :cond_b

    iget-object v6, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    invoke-virtual {v6}, La/e/b/h/d;->c()Z

    move-result v8

    if-nez v8, :cond_a

    invoke-virtual {v0, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    :cond_a
    add-int/lit8 v5, v5, 0x1

    goto :goto_6

    :cond_b
    invoke-virtual {p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v3

    if-ne v3, v1, :cond_c

    move v12, v4

    goto :goto_7

    :cond_c
    move v12, v7

    :goto_7
    const/4 v13, 0x0

    move-object v8, p0

    move-object v9, p0

    move-object v10, p1

    move-object v11, v0

    invoke-virtual/range {v8 .. v13}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_13

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/d;

    invoke-static {p0, p1, v1}, La/e/b/h/i;->a(La/e/b/h/e;La/e/b/d;La/e/b/h/d;)V

    invoke-virtual {v1, p1, v2}, La/e/b/h/d;->d(La/e/b/d;Z)V

    goto :goto_8

    :cond_d
    move v5, v4

    :goto_9
    if-ge v5, v3, :cond_13

    iget-object v6, p0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/d;

    instance-of v8, v6, La/e/b/h/e;

    if-eqz v8, :cond_11

    iget-object v8, v6, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v9, v8, v4

    aget-object v10, v8, v7

    if-ne v9, v1, :cond_e

    .line 6
    aput-object v0, v8, v4

    :cond_e
    if-ne v10, v1, :cond_f

    .line 7
    iget-object v8, v6, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v0, v8, v7

    .line 8
    :cond_f
    invoke-virtual {v6, p1, v2}, La/e/b/h/d;->d(La/e/b/d;Z)V

    if-ne v9, v1, :cond_10

    invoke-virtual {v6, v9}, La/e/b/h/d;->I(La/e/b/h/d$a;)V

    :cond_10
    if-ne v10, v1, :cond_12

    invoke-virtual {v6, v10}, La/e/b/h/d;->L(La/e/b/h/d$a;)V

    goto :goto_a

    :cond_11
    invoke-static {p0, p1, v6}, La/e/b/h/i;->a(La/e/b/h/e;La/e/b/d;La/e/b/h/d;)V

    invoke-virtual {v6}, La/e/b/h/d;->c()Z

    move-result v8

    if-nez v8, :cond_12

    invoke-virtual {v6, p1, v2}, La/e/b/h/d;->d(La/e/b/d;Z)V

    :cond_12
    :goto_a
    add-int/lit8 v5, v5, 0x1

    goto :goto_9

    :cond_13
    iget v0, p0, La/e/b/h/e;->w0:I

    const/4 v1, 0x0

    if-lez v0, :cond_14

    invoke-static {p0, p1, v1, v4}, La/b/k/h$i;->a(La/e/b/h/e;La/e/b/d;Ljava/util/ArrayList;I)V

    :cond_14
    iget v0, p0, La/e/b/h/e;->x0:I

    if-lez v0, :cond_15

    invoke-static {p0, p1, v1, v7}, La/b/k/h$i;->a(La/e/b/h/e;La/e/b/d;Ljava/util/ArrayList;I)V

    :cond_15
    return v7
.end method

.method public S(La/e/b/h/c;)V
    .locals 2

    iget-object v0, p0, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, La/e/b/h/c;->c()I

    move-result v0

    iget-object v1, p0, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    if-le v0, v1, :cond_1

    :cond_0
    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, La/e/b/h/e;->G0:Ljava/lang/ref/WeakReference;

    :cond_1
    return-void
.end method

.method public T(La/e/b/h/c;)V
    .locals 2

    iget-object v0, p0, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, La/e/b/h/c;->c()I

    move-result v0

    iget-object v1, p0, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    if-le v0, v1, :cond_1

    :cond_0
    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, La/e/b/h/e;->F0:Ljava/lang/ref/WeakReference;

    :cond_1
    return-void
.end method

.method public U(La/e/b/h/c;)V
    .locals 2

    iget-object v0, p0, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, La/e/b/h/c;->c()I

    move-result v0

    iget-object v1, p0, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    if-le v0, v1, :cond_1

    :cond_0
    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, La/e/b/h/e;->D0:Ljava/lang/ref/WeakReference;

    :cond_1
    return-void
.end method

.method public V(ZI)Z
    .locals 13

    iget-object v0, p0, La/e/b/h/e;->q0:La/e/b/h/l/e;

    .line 1
    sget-object v1, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    sget-object v3, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    const/4 v4, 0x1

    and-int/2addr p1, v4

    iget-object v5, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    const/4 v6, 0x0

    invoke-virtual {v5, v6}, La/e/b/h/d;->k(I)La/e/b/h/d$a;

    move-result-object v5

    iget-object v7, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {v7, v4}, La/e/b/h/d;->k(I)La/e/b/h/d$a;

    move-result-object v7

    iget-object v8, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {v8}, La/e/b/h/d;->s()I

    move-result v8

    iget-object v9, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {v9}, La/e/b/h/d;->t()I

    move-result v9

    if-eqz p1, :cond_4

    if-eq v5, v2, :cond_0

    if-ne v7, v2, :cond_4

    :cond_0
    iget-object v10, v0, La/e/b/h/l/e;->e:Ljava/util/ArrayList;

    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :cond_1
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    if-eqz v11, :cond_2

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/e/b/h/l/o;

    iget v12, v11, La/e/b/h/l/o;->f:I

    if-ne v12, p2, :cond_1

    invoke-virtual {v11}, La/e/b/h/l/o;->k()Z

    move-result v11

    if-nez v11, :cond_1

    move p1, v6

    :cond_2
    if-nez p2, :cond_3

    if-eqz p1, :cond_4

    if-ne v5, v2, :cond_4

    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    .line 2
    iget-object v2, p1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v3, v2, v6

    .line 3
    invoke-virtual {v0, p1, v6}, La/e/b/h/l/e;->d(La/e/b/h/e;I)I

    move-result v2

    invoke-virtual {p1, v2}, La/e/b/h/d;->M(I)V

    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v2, p1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v2, v2, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p1}, La/e/b/h/d;->r()I

    move-result p1

    goto :goto_0

    :cond_3
    if-eqz p1, :cond_4

    if-ne v7, v2, :cond_4

    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    .line 4
    iget-object v2, p1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aput-object v3, v2, v4

    .line 5
    invoke-virtual {v0, p1, v4}, La/e/b/h/l/e;->d(La/e/b/h/e;I)I

    move-result v2

    invoke-virtual {p1, v2}, La/e/b/h/d;->H(I)V

    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v2, p1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v2, v2, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p1}, La/e/b/h/d;->l()I

    move-result p1

    :goto_0
    invoke-virtual {v2, p1}, La/e/b/h/l/g;->c(I)V

    :cond_4
    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object p1, p1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    if-nez p2, :cond_6

    aget-object v2, p1, v6

    if-eq v2, v3, :cond_5

    aget-object p1, p1, v6

    if-ne p1, v1, :cond_7

    :cond_5
    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {p1}, La/e/b/h/d;->r()I

    move-result p1

    add-int/2addr p1, v8

    iget-object v1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1, p1}, La/e/b/h/l/f;->c(I)V

    iget-object v1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    sub-int/2addr p1, v8

    goto :goto_2

    :cond_6
    aget-object v2, p1, v4

    if-eq v2, v3, :cond_8

    aget-object p1, p1, v4

    if-ne p1, v1, :cond_7

    goto :goto_1

    :cond_7
    move p1, v6

    goto :goto_3

    :cond_8
    :goto_1
    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {p1}, La/e/b/h/d;->l()I

    move-result p1

    add-int/2addr p1, v9

    iget-object v1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1, p1}, La/e/b/h/l/f;->c(I)V

    iget-object v1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    sub-int/2addr p1, v9

    :goto_2
    invoke-virtual {v1, p1}, La/e/b/h/l/g;->c(I)V

    move p1, v4

    :goto_3
    invoke-virtual {v0}, La/e/b/h/l/e;->g()V

    iget-object v1, v0, La/e/b/h/l/e;->e:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_b

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/o;

    iget v3, v2, La/e/b/h/l/o;->f:I

    if-eq v3, p2, :cond_9

    goto :goto_4

    :cond_9
    iget-object v3, v2, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v8, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    if-ne v3, v8, :cond_a

    iget-boolean v3, v2, La/e/b/h/l/o;->g:Z

    if-nez v3, :cond_a

    goto :goto_4

    :cond_a
    invoke-virtual {v2}, La/e/b/h/l/o;->e()V

    goto :goto_4

    :cond_b
    iget-object v1, v0, La/e/b/h/l/e;->e:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_c
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_11

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/o;

    iget v3, v2, La/e/b/h/l/o;->f:I

    if-eq v3, p2, :cond_d

    goto :goto_5

    :cond_d
    if-nez p1, :cond_e

    iget-object v3, v2, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v8, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    if-ne v3, v8, :cond_e

    goto :goto_5

    :cond_e
    iget-object v3, v2, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v3, v3, La/e/b/h/l/f;->j:Z

    if-nez v3, :cond_f

    goto :goto_6

    :cond_f
    iget-object v3, v2, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v3, v3, La/e/b/h/l/f;->j:Z

    if-nez v3, :cond_10

    goto :goto_6

    :cond_10
    instance-of v3, v2, La/e/b/h/l/c;

    if-nez v3, :cond_c

    iget-object v2, v2, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v2, v2, La/e/b/h/l/f;->j:Z

    if-nez v2, :cond_c

    :goto_6
    move v4, v6

    :cond_11
    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {p1, v5}, La/e/b/h/d;->I(La/e/b/h/d$a;)V

    iget-object p1, v0, La/e/b/h/l/e;->a:La/e/b/h/e;

    invoke-virtual {p1, v7}, La/e/b/h/d;->L(La/e/b/h/d$a;)V

    return v4
.end method

.method public W()V
    .locals 2

    iget-object v0, p0, La/e/b/h/e;->q0:La/e/b/h/l/e;

    const/4 v1, 0x1

    .line 1
    iput-boolean v1, v0, La/e/b/h/l/e;->b:Z

    return-void
.end method

.method public Y(I)Z
    .locals 1

    iget v0, p0, La/e/b/h/e;->A0:I

    and-int/2addr v0, p1

    if-ne v0, p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return p1
.end method

.method public Z(I)V
    .locals 0

    iput p1, p0, La/e/b/h/e;->A0:I

    const/16 p1, 0x200

    invoke-virtual {p0, p1}, La/e/b/h/e;->Y(I)Z

    move-result p1

    sput-boolean p1, La/e/b/d;->r:Z

    return-void
.end method
