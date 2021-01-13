.class public La/e/b/h/l/c;
.super La/e/b/h/l/o;
.source ""


# instance fields
.field public k:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/o;",
            ">;"
        }
    .end annotation
.end field

.field public l:I


# direct methods
.method public constructor <init>(La/e/b/h/d;I)V
    .locals 3

    invoke-direct {p0, p1}, La/e/b/h/l/o;-><init>(La/e/b/h/d;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    iput p2, p0, La/e/b/h/l/o;->f:I

    .line 1
    iget-object p1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    :goto_0
    iget p2, p0, La/e/b/h/l/o;->f:I

    invoke-virtual {p1, p2}, La/e/b/h/d;->o(I)La/e/b/h/d;

    move-result-object p2

    if-eqz p2, :cond_0

    move-object p1, p2

    goto :goto_0

    :cond_0
    iput-object p1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object p2, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    iget v0, p0, La/e/b/h/l/o;->f:I

    const/4 v1, 0x1

    if-nez v0, :cond_1

    move-object v0, p0

    goto :goto_2

    :cond_1
    if-ne v0, v1, :cond_2

    move-object v0, p0

    goto :goto_3

    :cond_2
    move-object v0, p0

    :cond_3
    const/4 v2, 0x0

    :goto_1
    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget p2, v0, La/e/b/h/l/o;->f:I

    invoke-virtual {p1, p2}, La/e/b/h/d;->n(I)La/e/b/h/d;

    move-result-object p1

    if-eqz p1, :cond_5

    iget-object p2, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    iget v2, v0, La/e/b/h/l/o;->f:I

    if-nez v2, :cond_4

    .line 2
    :goto_2
    iget-object v2, p1, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_1

    :cond_4
    if-ne v2, v1, :cond_3

    :goto_3
    iget-object v2, p1, La/e/b/h/d;->e:La/e/b/h/l/m;

    goto :goto_1

    .line 3
    :cond_5
    iget-object p1, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_6
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_8

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, La/e/b/h/l/o;

    iget v2, v0, La/e/b/h/l/o;->f:I

    if-nez v2, :cond_7

    iget-object p2, p2, La/e/b/h/l/o;->b:La/e/b/h/d;

    iput-object v0, p2, La/e/b/h/d;->b:La/e/b/h/l/c;

    goto :goto_4

    :cond_7
    if-ne v2, v1, :cond_6

    iget-object p2, p2, La/e/b/h/l/o;->b:La/e/b/h/d;

    iput-object v0, p2, La/e/b/h/d;->c:La/e/b/h/l/c;

    goto :goto_4

    :cond_8
    iget p1, v0, La/e/b/h/l/o;->f:I

    if-nez p1, :cond_9

    iget-object p1, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 4
    iget-object p1, p1, La/e/b/h/d;->R:La/e/b/h/d;

    .line 5
    check-cast p1, La/e/b/h/e;

    .line 6
    iget-boolean p1, p1, La/e/b/h/e;->s0:Z

    if-eqz p1, :cond_9

    move p1, v1

    goto :goto_5

    :cond_9
    const/4 p1, 0x0

    :goto_5
    if-eqz p1, :cond_a

    .line 7
    iget-object p1, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    if-le p1, v1, :cond_a

    iget-object p1, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p2

    sub-int/2addr p2, v1

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/e/b/h/l/o;

    iget-object p1, p1, La/e/b/h/l/o;->b:La/e/b/h/d;

    iput-object p1, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    :cond_a
    iget p1, v0, La/e/b/h/l/o;->f:I

    if-nez p1, :cond_b

    iget-object p1, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 8
    iget p1, p1, La/e/b/h/d;->h0:I

    goto :goto_6

    .line 9
    :cond_b
    iget-object p1, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 10
    iget p1, p1, La/e/b/h/d;->i0:I

    .line 11
    :goto_6
    iput p1, v0, La/e/b/h/l/c;->l:I

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 24

    move-object/from16 v0, p0

    sget-object v1, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    iget-object v2, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v2, v2, La/e/b/h/l/f;->j:Z

    if-eqz v2, :cond_57

    iget-object v2, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v2, v2, La/e/b/h/l/f;->j:Z

    if-nez v2, :cond_0

    goto/16 :goto_32

    :cond_0
    iget-object v2, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget-object v2, v2, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v2, :cond_1

    .line 2
    instance-of v4, v2, La/e/b/h/e;

    if-eqz v4, :cond_1

    check-cast v2, La/e/b/h/e;

    .line 3
    iget-boolean v2, v2, La/e/b/h/e;->s0:Z

    goto :goto_0

    :cond_1
    const/4 v2, 0x0

    .line 4
    :goto_0
    iget-object v4, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->g:I

    iget-object v5, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v5, v5, La/e/b/h/l/f;->g:I

    sub-int/2addr v4, v5

    iget-object v5, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v5

    const/4 v6, 0x0

    :goto_1
    const/4 v7, -0x1

    const/16 v8, 0x8

    if-ge v6, v5, :cond_2

    iget-object v9, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, La/e/b/h/l/o;

    iget-object v9, v9, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 5
    iget v9, v9, La/e/b/h/d;->e0:I

    if-ne v9, v8, :cond_3

    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_2
    move v6, v7

    :cond_3
    add-int/lit8 v9, v5, -0x1

    move v10, v9

    :goto_2
    if-ltz v10, :cond_5

    .line 6
    iget-object v11, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v11, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/e/b/h/l/o;

    iget-object v11, v11, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 7
    iget v11, v11, La/e/b/h/d;->e0:I

    if-ne v11, v8, :cond_4

    add-int/lit8 v10, v10, -0x1

    goto :goto_2

    :cond_4
    move v7, v10

    :cond_5
    const/4 v10, 0x0

    :goto_3
    const/4 v12, 0x2

    const/4 v13, 0x1

    if-ge v10, v12, :cond_13

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    :goto_4
    if-ge v14, v5, :cond_10

    .line 8
    iget-object v3, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/l/o;

    iget-object v12, v3, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 9
    iget v12, v12, La/e/b/h/d;->e0:I

    if-ne v12, v8, :cond_6

    goto/16 :goto_8

    :cond_6
    add-int/lit8 v17, v17, 0x1

    if-lez v14, :cond_7

    if-lt v14, v6, :cond_7

    .line 10
    iget-object v12, v3, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v12, v12, La/e/b/h/l/f;->f:I

    add-int/2addr v15, v12

    :cond_7
    iget-object v12, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v12, v12, La/e/b/h/l/f;->g:I

    iget-object v8, v3, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-eq v8, v1, :cond_8

    move v8, v13

    goto :goto_5

    :cond_8
    const/4 v8, 0x0

    :goto_5
    if-eqz v8, :cond_a

    iget v11, v0, La/e/b/h/l/o;->f:I

    if-nez v11, :cond_9

    iget-object v11, v3, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v11, v11, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v11, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v11, v11, La/e/b/h/l/f;->j:Z

    if-nez v11, :cond_9

    return-void

    :cond_9
    iget v11, v0, La/e/b/h/l/o;->f:I

    if-ne v11, v13, :cond_c

    iget-object v11, v3, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v11, v11, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v11, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v11, v11, La/e/b/h/l/f;->j:Z

    if-nez v11, :cond_c

    return-void

    :cond_a
    iget v11, v3, La/e/b/h/l/o;->a:I

    if-ne v11, v13, :cond_b

    if-nez v10, :cond_b

    iget-object v8, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v12, v8, La/e/b/h/l/g;->m:I

    add-int/lit8 v16, v16, 0x1

    goto :goto_6

    :cond_b
    iget-object v11, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v11, v11, La/e/b/h/l/f;->j:Z

    if-eqz v11, :cond_c

    :goto_6
    move v8, v13

    :cond_c
    if-nez v8, :cond_d

    add-int/lit8 v16, v16, 0x1

    iget-object v8, v3, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v8, v8, La/e/b/h/d;->j0:[F

    iget v11, v0, La/e/b/h/l/o;->f:I

    aget v8, v8, v11

    const/4 v11, 0x0

    cmpl-float v12, v8, v11

    if-ltz v12, :cond_e

    add-float v18, v18, v8

    goto :goto_7

    :cond_d
    add-int/2addr v15, v12

    :cond_e
    :goto_7
    if-ge v14, v9, :cond_f

    if-ge v14, v7, :cond_f

    iget-object v3, v3, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v3, v3, La/e/b/h/l/f;->f:I

    neg-int v3, v3

    add-int/2addr v15, v3

    :cond_f
    :goto_8
    add-int/lit8 v14, v14, 0x1

    const/16 v8, 0x8

    const/4 v12, 0x2

    goto/16 :goto_4

    :cond_10
    if-lt v15, v4, :cond_12

    if-nez v16, :cond_11

    goto :goto_9

    :cond_11
    add-int/lit8 v10, v10, 0x1

    const/16 v8, 0x8

    goto/16 :goto_3

    :cond_12
    :goto_9
    move/from16 v3, v16

    move/from16 v8, v17

    goto :goto_a

    :cond_13
    const/4 v3, 0x0

    const/4 v8, 0x0

    const/4 v15, 0x0

    const/16 v18, 0x0

    :goto_a
    iget-object v10, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v10, v10, La/e/b/h/l/f;->g:I

    if-eqz v2, :cond_14

    iget-object v10, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v10, v10, La/e/b/h/l/f;->g:I

    :cond_14
    const/high16 v11, 0x3f000000    # 0.5f

    if-le v15, v4, :cond_16

    const/high16 v12, 0x40000000    # 2.0f

    sub-int v14, v15, v4

    int-to-float v14, v14

    div-float/2addr v14, v12

    add-float/2addr v14, v11

    float-to-int v12, v14

    if-eqz v2, :cond_15

    add-int/2addr v10, v12

    goto :goto_b

    :cond_15
    sub-int/2addr v10, v12

    :cond_16
    :goto_b
    if-lez v3, :cond_27

    sub-int v12, v4, v15

    int-to-float v12, v12

    int-to-float v14, v3

    div-float v14, v12, v14

    add-float/2addr v14, v11

    float-to-int v14, v14

    const/4 v13, 0x0

    const/16 v17, 0x0

    :goto_c
    if-ge v13, v5, :cond_20

    iget-object v11, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/e/b/h/l/o;

    move/from16 v19, v14

    iget-object v14, v11, La/e/b/h/l/o;->b:La/e/b/h/d;

    move/from16 v20, v15

    .line 11
    iget v15, v14, La/e/b/h/d;->e0:I

    move/from16 v21, v10

    const/16 v10, 0x8

    if-ne v15, v10, :cond_17

    goto/16 :goto_11

    .line 12
    :cond_17
    iget-object v10, v11, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v10, v1, :cond_1f

    iget-object v10, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v10, v10, La/e/b/h/l/f;->j:Z

    if-nez v10, :cond_1f

    const/4 v10, 0x0

    cmpl-float v15, v18, v10

    if-lez v15, :cond_18

    iget-object v14, v14, La/e/b/h/d;->j0:[F

    iget v15, v0, La/e/b/h/l/o;->f:I

    aget v14, v14, v15

    mul-float/2addr v14, v12

    div-float v14, v14, v18

    const/high16 v15, 0x3f000000    # 0.5f

    add-float/2addr v14, v15

    float-to-int v14, v14

    goto :goto_d

    :cond_18
    move/from16 v14, v19

    :goto_d
    iget v15, v0, La/e/b/h/l/o;->f:I

    if-nez v15, :cond_1b

    iget-object v15, v11, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v10, v15, La/e/b/h/d;->r:I

    iget v15, v15, La/e/b/h/d;->q:I

    move/from16 v22, v12

    iget v12, v11, La/e/b/h/l/o;->a:I

    move-object/from16 v23, v1

    const/4 v1, 0x1

    if-ne v12, v1, :cond_19

    iget-object v1, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v1, v1, La/e/b/h/l/g;->m:I

    invoke-static {v14, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    goto :goto_e

    :cond_19
    move v1, v14

    :goto_e
    invoke-static {v15, v1}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-lez v10, :cond_1a

    invoke-static {v10, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    :cond_1a
    if-eq v1, v14, :cond_1e

    goto :goto_10

    :cond_1b
    move-object/from16 v23, v1

    move/from16 v22, v12

    iget-object v1, v11, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v10, v1, La/e/b/h/d;->u:I

    iget v1, v1, La/e/b/h/d;->t:I

    iget v12, v11, La/e/b/h/l/o;->a:I

    const/4 v15, 0x1

    if-ne v12, v15, :cond_1c

    iget-object v12, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v12, v12, La/e/b/h/l/g;->m:I

    invoke-static {v14, v12}, Ljava/lang/Math;->min(II)I

    move-result v12

    goto :goto_f

    :cond_1c
    move v12, v14

    :goto_f
    invoke-static {v1, v12}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-lez v10, :cond_1d

    invoke-static {v10, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    :cond_1d
    if-eq v1, v14, :cond_1e

    :goto_10
    add-int/lit8 v17, v17, 0x1

    move v14, v1

    :cond_1e
    iget-object v1, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v1, v14}, La/e/b/h/l/g;->c(I)V

    goto :goto_12

    :cond_1f
    :goto_11
    move-object/from16 v23, v1

    move/from16 v22, v12

    :goto_12
    add-int/lit8 v13, v13, 0x1

    move/from16 v14, v19

    move/from16 v15, v20

    move/from16 v10, v21

    move/from16 v12, v22

    move-object/from16 v1, v23

    const/high16 v11, 0x3f000000    # 0.5f

    goto/16 :goto_c

    :cond_20
    move-object/from16 v23, v1

    move/from16 v21, v10

    move/from16 v20, v15

    if-lez v17, :cond_25

    sub-int v3, v3, v17

    const/4 v1, 0x0

    const/4 v10, 0x0

    :goto_13
    if-ge v1, v5, :cond_24

    iget-object v11, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/e/b/h/l/o;

    iget-object v12, v11, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 13
    iget v12, v12, La/e/b/h/d;->e0:I

    const/16 v13, 0x8

    if-ne v12, v13, :cond_21

    goto :goto_14

    :cond_21
    if-lez v1, :cond_22

    if-lt v1, v6, :cond_22

    .line 14
    iget-object v12, v11, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v12, v12, La/e/b/h/l/f;->f:I

    add-int/2addr v10, v12

    :cond_22
    iget-object v12, v11, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v12, v12, La/e/b/h/l/f;->g:I

    add-int/2addr v10, v12

    if-ge v1, v9, :cond_23

    if-ge v1, v7, :cond_23

    iget-object v11, v11, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v11, v11, La/e/b/h/l/f;->f:I

    neg-int v11, v11

    add-int/2addr v10, v11

    :cond_23
    :goto_14
    add-int/lit8 v1, v1, 0x1

    goto :goto_13

    :cond_24
    move v15, v10

    goto :goto_15

    :cond_25
    move/from16 v15, v20

    :goto_15
    iget v1, v0, La/e/b/h/l/c;->l:I

    const/4 v10, 0x2

    if-ne v1, v10, :cond_26

    if-nez v17, :cond_26

    const/4 v1, 0x0

    iput v1, v0, La/e/b/h/l/c;->l:I

    goto :goto_16

    :cond_26
    const/4 v1, 0x0

    goto :goto_16

    :cond_27
    move-object/from16 v23, v1

    move/from16 v21, v10

    move/from16 v20, v15

    const/4 v1, 0x0

    const/4 v10, 0x2

    :goto_16
    if-le v15, v4, :cond_28

    iput v10, v0, La/e/b/h/l/c;->l:I

    :cond_28
    if-lez v8, :cond_29

    if-nez v3, :cond_29

    if-ne v6, v7, :cond_29

    iput v10, v0, La/e/b/h/l/c;->l:I

    :cond_29
    iget v10, v0, La/e/b/h/l/c;->l:I

    const/4 v11, 0x1

    if-ne v10, v11, :cond_39

    if-le v8, v11, :cond_2a

    sub-int/2addr v4, v15

    sub-int/2addr v8, v11

    div-int/2addr v4, v8

    goto :goto_17

    :cond_2a
    if-ne v8, v11, :cond_2b

    sub-int/2addr v4, v15

    const/4 v8, 0x2

    div-int/2addr v4, v8

    goto :goto_17

    :cond_2b
    move v4, v1

    :goto_17
    if-lez v3, :cond_2c

    move v4, v1

    :cond_2c
    move v3, v1

    move/from16 v10, v21

    :goto_18
    if-ge v3, v5, :cond_57

    if-eqz v2, :cond_2d

    add-int/lit8 v1, v3, 0x1

    sub-int v1, v5, v1

    goto :goto_19

    :cond_2d
    move v1, v3

    :goto_19
    iget-object v8, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v8, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 15
    iget v8, v8, La/e/b/h/d;->e0:I

    const/16 v11, 0x8

    if-ne v8, v11, :cond_2e

    .line 16
    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1, v10}, La/e/b/h/l/f;->c(I)V

    move-object/from16 v13, v23

    goto :goto_1f

    :cond_2e
    if-lez v3, :cond_30

    if-eqz v2, :cond_2f

    sub-int/2addr v10, v4

    goto :goto_1a

    :cond_2f
    add-int/2addr v10, v4

    :cond_30
    :goto_1a
    if-lez v3, :cond_32

    if-lt v3, v6, :cond_32

    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v8, v8, La/e/b/h/l/f;->f:I

    if-eqz v2, :cond_31

    sub-int/2addr v10, v8

    goto :goto_1b

    :cond_31
    add-int/2addr v10, v8

    :cond_32
    :goto_1b
    if-eqz v2, :cond_33

    iget-object v8, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    goto :goto_1c

    :cond_33
    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    :goto_1c
    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v8, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v11, v8, La/e/b/h/l/f;->g:I

    iget-object v12, v1, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    move-object/from16 v13, v23

    if-ne v12, v13, :cond_34

    iget v12, v1, La/e/b/h/l/o;->a:I

    const/4 v14, 0x1

    if-ne v12, v14, :cond_34

    iget v11, v8, La/e/b/h/l/g;->m:I

    :cond_34
    if-eqz v2, :cond_35

    sub-int/2addr v10, v11

    goto :goto_1d

    :cond_35
    add-int/2addr v10, v11

    :goto_1d
    if-eqz v2, :cond_36

    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto :goto_1e

    :cond_36
    iget-object v8, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    :goto_1e
    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    const/4 v8, 0x1

    iput-boolean v8, v1, La/e/b/h/l/o;->g:Z

    if-ge v3, v9, :cond_38

    if-ge v3, v7, :cond_38

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    neg-int v1, v1

    if-eqz v2, :cond_37

    sub-int/2addr v10, v1

    goto :goto_1f

    :cond_37
    add-int/2addr v10, v1

    :cond_38
    :goto_1f
    add-int/lit8 v3, v3, 0x1

    move-object/from16 v23, v13

    goto :goto_18

    :cond_39
    move-object/from16 v13, v23

    if-nez v10, :cond_46

    sub-int/2addr v4, v15

    const/4 v10, 0x1

    add-int/2addr v8, v10

    div-int/2addr v4, v8

    if-lez v3, :cond_3a

    move v4, v1

    :cond_3a
    move v3, v1

    move/from16 v10, v21

    :goto_20
    if-ge v3, v5, :cond_57

    if-eqz v2, :cond_3b

    add-int/lit8 v1, v3, 0x1

    sub-int v1, v5, v1

    goto :goto_21

    :cond_3b
    move v1, v3

    :goto_21
    iget-object v8, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v8, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 17
    iget v8, v8, La/e/b/h/d;->e0:I

    const/16 v11, 0x8

    if-ne v8, v11, :cond_3c

    .line 18
    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1, v10}, La/e/b/h/l/f;->c(I)V

    goto :goto_27

    :cond_3c
    if-eqz v2, :cond_3d

    sub-int/2addr v10, v4

    goto :goto_22

    :cond_3d
    add-int/2addr v10, v4

    :goto_22
    if-lez v3, :cond_3f

    if-lt v3, v6, :cond_3f

    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v8, v8, La/e/b/h/l/f;->f:I

    if-eqz v2, :cond_3e

    sub-int/2addr v10, v8

    goto :goto_23

    :cond_3e
    add-int/2addr v10, v8

    :cond_3f
    :goto_23
    if-eqz v2, :cond_40

    iget-object v8, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    goto :goto_24

    :cond_40
    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    :goto_24
    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v8, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v11, v8, La/e/b/h/l/f;->g:I

    iget-object v12, v1, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v12, v13, :cond_41

    iget v12, v1, La/e/b/h/l/o;->a:I

    const/4 v14, 0x1

    if-ne v12, v14, :cond_41

    iget v8, v8, La/e/b/h/l/g;->m:I

    invoke-static {v11, v8}, Ljava/lang/Math;->min(II)I

    move-result v11

    :cond_41
    if-eqz v2, :cond_42

    sub-int/2addr v10, v11

    goto :goto_25

    :cond_42
    add-int/2addr v10, v11

    :goto_25
    if-eqz v2, :cond_43

    iget-object v8, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto :goto_26

    :cond_43
    iget-object v8, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    :goto_26
    invoke-virtual {v8, v10}, La/e/b/h/l/f;->c(I)V

    if-ge v3, v9, :cond_45

    if-ge v3, v7, :cond_45

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    neg-int v1, v1

    if-eqz v2, :cond_44

    sub-int/2addr v10, v1

    goto :goto_27

    :cond_44
    add-int/2addr v10, v1

    :cond_45
    :goto_27
    add-int/lit8 v3, v3, 0x1

    goto :goto_20

    :cond_46
    const/4 v8, 0x2

    if-ne v10, v8, :cond_57

    iget v8, v0, La/e/b/h/l/o;->f:I

    if-nez v8, :cond_47

    iget-object v8, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 19
    iget v8, v8, La/e/b/h/d;->b0:F

    goto :goto_28

    .line 20
    :cond_47
    iget-object v8, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 21
    iget v8, v8, La/e/b/h/d;->c0:F

    :goto_28
    if-eqz v2, :cond_48

    const/high16 v10, 0x3f800000    # 1.0f

    sub-float v8, v10, v8

    :cond_48
    sub-int/2addr v4, v15

    int-to-float v4, v4

    mul-float/2addr v4, v8

    const/high16 v8, 0x3f000000    # 0.5f

    add-float/2addr v4, v8

    float-to-int v4, v4

    if-ltz v4, :cond_49

    if-lez v3, :cond_4a

    :cond_49
    move v4, v1

    :cond_4a
    if-eqz v2, :cond_4b

    sub-int v10, v21, v4

    goto :goto_29

    :cond_4b
    add-int v10, v21, v4

    :goto_29
    move v3, v1

    :goto_2a
    if-ge v3, v5, :cond_57

    if-eqz v2, :cond_4c

    add-int/lit8 v1, v3, 0x1

    sub-int v1, v5, v1

    goto :goto_2b

    :cond_4c
    move v1, v3

    .line 22
    :goto_2b
    iget-object v4, v0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v4, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 23
    iget v4, v4, La/e/b/h/d;->e0:I

    const/16 v8, 0x8

    if-ne v4, v8, :cond_4d

    .line 24
    iget-object v4, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v4, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1, v10}, La/e/b/h/l/f;->c(I)V

    const/4 v14, 0x1

    goto :goto_31

    :cond_4d
    if-lez v3, :cond_4f

    if-lt v3, v6, :cond_4f

    iget-object v4, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    if-eqz v2, :cond_4e

    sub-int/2addr v10, v4

    goto :goto_2c

    :cond_4e
    add-int/2addr v10, v4

    :cond_4f
    :goto_2c
    if-eqz v2, :cond_50

    iget-object v4, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    goto :goto_2d

    :cond_50
    iget-object v4, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    :goto_2d
    invoke-virtual {v4, v10}, La/e/b/h/l/f;->c(I)V

    iget-object v4, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v11, v4, La/e/b/h/l/f;->g:I

    iget-object v12, v1, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v12, v13, :cond_51

    iget v12, v1, La/e/b/h/l/o;->a:I

    const/4 v14, 0x1

    if-ne v12, v14, :cond_52

    iget v11, v4, La/e/b/h/l/g;->m:I

    goto :goto_2e

    :cond_51
    const/4 v14, 0x1

    :cond_52
    :goto_2e
    if-eqz v2, :cond_53

    sub-int/2addr v10, v11

    goto :goto_2f

    :cond_53
    add-int/2addr v10, v11

    :goto_2f
    if-eqz v2, :cond_54

    iget-object v4, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto :goto_30

    :cond_54
    iget-object v4, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    :goto_30
    invoke-virtual {v4, v10}, La/e/b/h/l/f;->c(I)V

    if-ge v3, v9, :cond_56

    if-ge v3, v7, :cond_56

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    neg-int v1, v1

    if-eqz v2, :cond_55

    sub-int/2addr v10, v1

    goto :goto_31

    :cond_55
    add-int/2addr v10, v1

    :cond_56
    :goto_31
    add-int/lit8 v3, v3, 0x1

    goto :goto_2a

    :cond_57
    :goto_32
    return-void
.end method

.method public d()V
    .locals 6

    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    invoke-virtual {v1}, La/e/b/h/l/o;->d()V

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x1

    if-ge v0, v1, :cond_1

    return-void

    :cond_1
    iget-object v2, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/o;

    iget-object v2, v2, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v4, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    sub-int/2addr v0, v1

    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/o;

    iget-object v0, v0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v4, p0, La/e/b/h/l/o;->f:I

    if-nez v4, :cond_5

    iget-object v1, v2, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p0, v1, v3}, La/e/b/h/l/o;->i(La/e/b/h/c;I)La/e/b/h/l/f;

    move-result-object v2

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    invoke-virtual {p0}, La/e/b/h/l/c;->m()La/e/b/h/d;

    move-result-object v4

    if-eqz v4, :cond_2

    iget-object v1, v4, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    :cond_2
    if-eqz v2, :cond_3

    iget-object v4, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    .line 1
    iget-object v5, v4, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v5, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v1, v4, La/e/b/h/l/f;->f:I

    iget-object v1, v2, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v1, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2
    :cond_3
    invoke-virtual {p0, v0, v3}, La/e/b/h/l/o;->i(La/e/b/h/c;I)La/e/b/h/l/f;

    move-result-object v1

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v0

    invoke-virtual {p0}, La/e/b/h/l/c;->n()La/e/b/h/d;

    move-result-object v2

    if-eqz v2, :cond_4

    iget-object v0, v2, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v0

    :cond_4
    if-eqz v1, :cond_9

    :goto_1
    iget-object v2, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    neg-int v0, v0

    .line 3
    iget-object v3, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v0, v2, La/e/b/h/l/f;->f:I

    iget-object v0, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 4
    :cond_5
    iget-object v2, v2, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p0, v2, v1}, La/e/b/h/l/o;->i(La/e/b/h/c;I)La/e/b/h/l/f;

    move-result-object v3

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    invoke-virtual {p0}, La/e/b/h/l/c;->m()La/e/b/h/d;

    move-result-object v4

    if-eqz v4, :cond_6

    iget-object v2, v4, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    :cond_6
    if-eqz v3, :cond_7

    iget-object v4, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    .line 5
    iget-object v5, v4, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v5, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v4, La/e/b/h/l/f;->f:I

    iget-object v2, v3, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v2, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 6
    :cond_7
    invoke-virtual {p0, v0, v1}, La/e/b/h/l/o;->i(La/e/b/h/c;I)La/e/b/h/l/f;

    move-result-object v1

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v0

    invoke-virtual {p0}, La/e/b/h/l/c;->n()La/e/b/h/d;

    move-result-object v2

    if-eqz v2, :cond_8

    iget-object v0, v2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v0

    :cond_8
    if-eqz v1, :cond_9

    goto :goto_1

    :cond_9
    :goto_2
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iput-object p0, v0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iput-object p0, v0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    return-void
.end method

.method public e()V
    .locals 2

    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge v0, v1, :cond_0

    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    invoke-virtual {v1}, La/e/b/h/l/o;->e()V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public f()V
    .locals 2

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/o;->c:La/e/b/h/l/l;

    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    invoke-virtual {v1}, La/e/b/h/l/o;->f()V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public j()J
    .locals 7

    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const-wide/16 v1, 0x0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v0, :cond_0

    iget-object v4, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, La/e/b/h/l/o;

    iget-object v5, v4, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v5, v5, La/e/b/h/l/f;->f:I

    int-to-long v5, v5

    add-long/2addr v1, v5

    invoke-virtual {v4}, La/e/b/h/l/o;->j()J

    move-result-wide v5

    add-long/2addr v5, v1

    iget-object v1, v4, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    int-to-long v1, v1

    add-long/2addr v1, v5

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-wide v1
.end method

.method public k()Z
    .locals 4

    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_1

    iget-object v3, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/l/o;

    invoke-virtual {v3}, La/e/b/h/l/o;->k()Z

    move-result v3

    if-nez v3, :cond_0

    return v1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x1

    return v0
.end method

.method public final m()La/e/b/h/d;
    .locals 4

    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge v0, v1, :cond_1

    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v1, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget v2, v1, La/e/b/h/d;->e0:I

    const/16 v3, 0x8

    if-eq v2, v3, :cond_0

    return-object v1

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public final n()La/e/b/h/d;
    .locals 4

    iget-object v0, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_1

    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v1, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget v2, v1, La/e/b/h/d;->e0:I

    const/16 v3, 0x8

    if-eq v2, v3, :cond_0

    return-object v1

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    const-string v0, "ChainRun "

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget v1, p0, La/e/b/h/l/o;->f:I

    if-nez v1, :cond_0

    const-string v1, "horizontal : "

    goto :goto_0

    :cond_0
    const-string v1, "vertical : "

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, La/e/b/h/l/c;->k:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/o;

    const-string v3, "<"

    invoke-static {v0, v3}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v2, "> "

    invoke-static {v0, v2}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_1

    :cond_1
    return-object v0
.end method
