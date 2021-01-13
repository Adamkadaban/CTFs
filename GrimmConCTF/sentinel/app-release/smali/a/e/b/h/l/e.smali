.class public La/e/b/h/l/e;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public a:La/e/b/h/e;

.field public b:Z

.field public c:Z

.field public d:La/e/b/h/e;

.field public e:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/o;",
            ">;"
        }
    .end annotation
.end field

.field public f:La/e/b/h/l/b$b;

.field public g:La/e/b/h/l/b$a;

.field public h:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/l;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(La/e/b/h/e;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    iput-boolean v0, p0, La/e/b/h/l/e;->b:Z

    iput-boolean v0, p0, La/e/b/h/l/e;->c:Z

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, La/e/b/h/l/e;->e:Ljava/util/ArrayList;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/e;->f:La/e/b/h/l/b$b;

    new-instance v0, La/e/b/h/l/b$a;

    invoke-direct {v0}, La/e/b/h/l/b$a;-><init>()V

    iput-object v0, p0, La/e/b/h/l/e;->g:La/e/b/h/l/b$a;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    iput-object p1, p0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iput-object p1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    return-void
.end method


# virtual methods
.method public final a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/e/b/h/l/f;",
            "II",
            "La/e/b/h/l/f;",
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/l;",
            ">;",
            "La/e/b/h/l/l;",
            ")V"
        }
    .end annotation

    iget-object p1, p1, La/e/b/h/l/f;->d:La/e/b/h/l/o;

    iget-object v0, p1, La/e/b/h/l/o;->c:La/e/b/h/l/l;

    if-nez v0, :cond_a

    iget-object v0, p0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v1, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    if-eq p1, v1, :cond_a

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    if-ne p1, v0, :cond_0

    goto/16 :goto_6

    :cond_0
    if-nez p6, :cond_1

    new-instance p6, La/e/b/h/l/l;

    invoke-direct {p6, p1, p3}, La/e/b/h/l/l;-><init>(La/e/b/h/l/o;I)V

    invoke-virtual {p5, p6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    iput-object p6, p1, La/e/b/h/l/o;->c:La/e/b/h/l/l;

    .line 1
    iget-object p3, p6, La/e/b/h/l/l;->b:Ljava/util/ArrayList;

    invoke-virtual {p3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2
    iget-object p3, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p3, p3, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :cond_2
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/d;

    instance-of v1, v0, La/e/b/h/l/f;

    if-eqz v1, :cond_2

    move-object v1, v0

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x0

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_0

    :cond_3
    iget-object p3, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object p3, p3, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :cond_4
    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/d;

    instance-of v1, v0, La/e/b/h/l/f;

    if-eqz v1, :cond_4

    move-object v1, v0

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x1

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_1

    :cond_5
    const/4 p3, 0x1

    if-ne p2, p3, :cond_7

    instance-of v0, p1, La/e/b/h/l/m;

    if-eqz v0, :cond_7

    move-object v0, p1

    check-cast v0, La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :cond_6
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/d;

    instance-of v1, v0, La/e/b/h/l/f;

    if-eqz v1, :cond_6

    move-object v1, v0

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x2

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_2

    :cond_7
    iget-object v0, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x0

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_3

    :cond_8
    iget-object v0, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x1

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_4

    :cond_9
    if-ne p2, p3, :cond_a

    instance-of p3, p1, La/e/b/h/l/m;

    if-eqz p3, :cond_a

    check-cast p1, La/e/b/h/l/m;

    iget-object p1, p1, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p3

    if-eqz p3, :cond_a

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p3

    move-object v1, p3

    check-cast v1, La/e/b/h/l/f;

    const/4 v3, 0x2

    move-object v0, p0

    move v2, p2

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_5

    :cond_a
    :goto_6
    return-void
.end method

.method public final b(La/e/b/h/e;)Z
    .locals 18

    move-object/from16 v0, p1

    sget-object v1, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    sget-object v9, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    sget-object v10, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    iget-object v3, v0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v11

    :cond_0
    :goto_0
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const/4 v4, 0x0

    if-eqz v3, :cond_27

    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v15, v3

    check-cast v15, La/e/b/h/d;

    iget-object v3, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v5, v3, v4

    const/4 v14, 0x1

    aget-object v3, v3, v14

    .line 1
    iget v6, v15, La/e/b/h/d;->e0:I

    const/16 v7, 0x8

    if-ne v6, v7, :cond_1

    .line 2
    :goto_1
    iput-boolean v14, v15, La/e/b/h/d;->a:Z

    goto :goto_0

    :cond_1
    iget v6, v15, La/e/b/h/d;->s:F

    const/high16 v12, 0x3f800000    # 1.0f

    cmpg-float v6, v6, v12

    const/4 v7, 0x2

    if-gez v6, :cond_2

    if-ne v5, v2, :cond_2

    iput v7, v15, La/e/b/h/d;->n:I

    :cond_2
    iget v6, v15, La/e/b/h/d;->v:F

    cmpg-float v6, v6, v12

    if-gez v6, :cond_3

    if-ne v3, v2, :cond_3

    iput v7, v15, La/e/b/h/d;->o:I

    .line 3
    :cond_3
    iget v6, v15, La/e/b/h/d;->U:F

    const/4 v8, 0x0

    cmpl-float v6, v6, v8

    const/4 v8, 0x3

    if-lez v6, :cond_9

    if-ne v5, v2, :cond_5

    if-eq v3, v9, :cond_4

    if-ne v3, v10, :cond_5

    .line 4
    :cond_4
    iput v8, v15, La/e/b/h/d;->n:I

    goto :goto_3

    :cond_5
    if-ne v3, v2, :cond_7

    if-eq v5, v9, :cond_6

    if-ne v5, v10, :cond_7

    :cond_6
    :goto_2
    iput v8, v15, La/e/b/h/d;->o:I

    goto :goto_3

    :cond_7
    if-ne v5, v2, :cond_9

    if-ne v3, v2, :cond_9

    iget v6, v15, La/e/b/h/d;->n:I

    if-nez v6, :cond_8

    iput v8, v15, La/e/b/h/d;->n:I

    :cond_8
    iget v6, v15, La/e/b/h/d;->o:I

    if-nez v6, :cond_9

    goto :goto_2

    :cond_9
    :goto_3
    if-ne v5, v2, :cond_b

    iget v6, v15, La/e/b/h/d;->n:I

    if-ne v6, v14, :cond_b

    iget-object v6, v15, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_a

    iget-object v6, v15, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v6, :cond_b

    :cond_a
    move-object v5, v9

    :cond_b
    if-ne v3, v2, :cond_d

    iget v6, v15, La/e/b/h/d;->o:I

    if-ne v6, v14, :cond_d

    iget-object v6, v15, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_c

    iget-object v6, v15, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v6, :cond_d

    :cond_c
    move-object v13, v9

    goto :goto_4

    :cond_d
    move-object v13, v3

    :goto_4
    iget-object v3, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iput-object v5, v3, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    iget v6, v15, La/e/b/h/d;->n:I

    iput v6, v3, La/e/b/h/l/o;->a:I

    iget-object v3, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iput-object v13, v3, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    iget v6, v15, La/e/b/h/d;->o:I

    iput v6, v3, La/e/b/h/l/o;->a:I

    if-eq v5, v1, :cond_e

    if-eq v5, v10, :cond_e

    if-ne v5, v9, :cond_f

    :cond_e
    if-eq v13, v1, :cond_24

    if-eq v13, v10, :cond_24

    if-ne v13, v9, :cond_f

    goto/16 :goto_e

    :cond_f
    const/high16 v16, 0x3f000000    # 0.5f

    if-ne v5, v2, :cond_17

    if-eq v13, v9, :cond_10

    if-ne v13, v10, :cond_17

    :cond_10
    iget v3, v15, La/e/b/h/d;->n:I

    if-ne v3, v8, :cond_12

    if-ne v13, v9, :cond_11

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v9

    move-object v7, v9

    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    :cond_11
    invoke-virtual {v15}, La/e/b/h/d;->l()I

    move-result v8

    int-to-float v3, v8

    iget v4, v15, La/e/b/h/d;->U:F

    mul-float/2addr v3, v4

    add-float v3, v3, v16

    float-to-int v6, v3

    :goto_5
    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v10

    :goto_6
    move-object v7, v10

    :goto_7
    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v3, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v4

    invoke-virtual {v3, v4}, La/e/b/h/l/g;->c(I)V

    iget-object v3, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v15}, La/e/b/h/d;->l()I

    move-result v4

    invoke-virtual {v3, v4}, La/e/b/h/l/g;->c(I)V

    goto/16 :goto_1

    :cond_12
    if-ne v3, v14, :cond_13

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v9

    move-object v7, v13

    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v3, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v4

    :goto_8
    iput v4, v3, La/e/b/h/l/g;->m:I

    goto/16 :goto_0

    :cond_13
    if-ne v3, v7, :cond_15

    iget-object v3, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v6, v3, v4

    if-eq v6, v10, :cond_14

    aget-object v3, v3, v4

    if-ne v3, v1, :cond_17

    :cond_14
    iget v3, v15, La/e/b/h/d;->s:F

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v4

    int-to-float v4, v4

    mul-float/2addr v3, v4

    add-float v3, v3, v16

    float-to-int v6, v3

    invoke-virtual {v15}, La/e/b/h/d;->l()I

    move-result v8

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v10

    goto :goto_a

    :cond_15
    iget-object v3, v15, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v3, v4

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_16

    aget-object v3, v3, v14

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v3, :cond_17

    :cond_16
    :goto_9
    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v9

    :goto_a
    move-object v7, v13

    goto :goto_7

    :cond_17
    if-ne v13, v2, :cond_1f

    if-eq v5, v9, :cond_18

    if-ne v5, v10, :cond_1f

    :cond_18
    iget v3, v15, La/e/b/h/d;->o:I

    if-ne v3, v8, :cond_1b

    if-ne v5, v9, :cond_19

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v9

    move-object v7, v9

    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    :cond_19
    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v6

    iget v3, v15, La/e/b/h/d;->U:F

    .line 5
    iget v4, v15, La/e/b/h/d;->V:I

    const/4 v5, -0x1

    if-ne v4, v5, :cond_1a

    div-float v3, v12, v3

    :cond_1a
    int-to-float v4, v6

    :goto_b
    mul-float/2addr v4, v3

    add-float v4, v4, v16

    float-to-int v8, v4

    goto/16 :goto_5

    :cond_1b
    if-ne v3, v14, :cond_1c

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v7, v9

    .line 6
    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    goto/16 :goto_d

    :cond_1c
    if-ne v3, v7, :cond_1e

    iget-object v3, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v6, v3, v14

    if-eq v6, v10, :cond_1d

    aget-object v3, v3, v14

    if-ne v3, v1, :cond_1f

    :cond_1d
    iget v3, v15, La/e/b/h/d;->v:F

    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v6

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v4

    int-to-float v4, v4

    mul-float/2addr v3, v4

    add-float v3, v3, v16

    float-to-int v8, v3

    move-object/from16 v3, p0

    move-object v4, v15

    goto/16 :goto_6

    :cond_1e
    iget-object v3, v15, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v3, v7

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_16

    aget-object v3, v3, v8

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v3, :cond_1f

    goto :goto_9

    :cond_1f
    if-ne v5, v2, :cond_0

    if-ne v13, v2, :cond_0

    iget v3, v15, La/e/b/h/d;->n:I

    if-eq v3, v14, :cond_23

    iget v5, v15, La/e/b/h/d;->o:I

    if-ne v5, v14, :cond_20

    goto :goto_c

    :cond_20
    if-ne v5, v7, :cond_0

    if-ne v3, v7, :cond_0

    iget-object v3, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v5, v3, v4

    if-eq v5, v10, :cond_21

    aget-object v3, v3, v4

    if-ne v3, v10, :cond_0

    :cond_21
    iget-object v3, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v4, v3, v14

    if-eq v4, v10, :cond_22

    aget-object v3, v3, v14

    if-ne v3, v10, :cond_0

    :cond_22
    iget v3, v15, La/e/b/h/d;->s:F

    iget v4, v15, La/e/b/h/d;->v:F

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v5

    int-to-float v5, v5

    mul-float/2addr v3, v5

    add-float v3, v3, v16

    float-to-int v6, v3

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v3

    int-to-float v3, v3

    goto :goto_b

    :cond_23
    :goto_c
    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object/from16 v3, p0

    move-object v4, v15

    move-object v5, v9

    move-object v7, v9

    invoke-virtual/range {v3 .. v8}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v3, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v4

    iput v4, v3, La/e/b/h/l/g;->m:I

    :goto_d
    iget-object v3, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v15}, La/e/b/h/d;->l()I

    move-result v4

    goto/16 :goto_8

    :cond_24
    :goto_e
    invoke-virtual {v15}, La/e/b/h/d;->r()I

    move-result v3

    if-ne v5, v1, :cond_25

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->r()I

    move-result v3

    iget-object v4, v15, La/e/b/h/d;->F:La/e/b/h/c;

    iget v4, v4, La/e/b/h/c;->g:I

    sub-int/2addr v3, v4

    iget-object v4, v15, La/e/b/h/d;->H:La/e/b/h/c;

    iget v4, v4, La/e/b/h/c;->g:I

    sub-int/2addr v3, v4

    move-object v5, v10

    :cond_25
    invoke-virtual {v15}, La/e/b/h/d;->l()I

    move-result v4

    if-ne v13, v1, :cond_26

    invoke-virtual/range {p1 .. p1}, La/e/b/h/d;->l()I

    move-result v4

    iget-object v6, v15, La/e/b/h/d;->G:La/e/b/h/c;

    iget v6, v6, La/e/b/h/c;->g:I

    sub-int/2addr v4, v6

    iget-object v6, v15, La/e/b/h/d;->I:La/e/b/h/c;

    iget v6, v6, La/e/b/h/c;->g:I

    sub-int/2addr v4, v6

    move/from16 v17, v4

    move-object/from16 v16, v10

    goto :goto_f

    :cond_26
    move/from16 v17, v4

    move-object/from16 v16, v13

    :goto_f
    move-object/from16 v12, p0

    move-object v13, v15

    move v4, v14

    move-object v14, v5

    move-object v5, v15

    move v15, v3

    invoke-virtual/range {v12 .. v17}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v3, v5, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v5}, La/e/b/h/d;->r()I

    move-result v6

    invoke-virtual {v3, v6}, La/e/b/h/l/g;->c(I)V

    iget-object v3, v5, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v5}, La/e/b/h/d;->l()I

    move-result v6

    invoke-virtual {v3, v6}, La/e/b/h/l/g;->c(I)V

    iput-boolean v4, v5, La/e/b/h/d;->a:Z

    goto/16 :goto_0

    :cond_27
    return v4
.end method

.method public c()V
    .locals 7

    iget-object v0, p0, La/e/b/h/l/e;->e:Ljava/util/ArrayList;

    .line 1
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    iget-object v1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    invoke-virtual {v1}, La/e/b/h/l/k;->f()V

    iget-object v1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    invoke-virtual {v1}, La/e/b/h/l/m;->f()V

    iget-object v1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v1, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    iget-object v1, v1, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v2, 0x0

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v3, :cond_8

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/d;

    instance-of v6, v3, La/e/b/h/f;

    if-eqz v6, :cond_1

    new-instance v4, La/e/b/h/l/i;

    invoke-direct {v4, v3}, La/e/b/h/l/i;-><init>(La/e/b/h/d;)V

    goto :goto_3

    :cond_1
    invoke-virtual {v3}, La/e/b/h/d;->w()Z

    move-result v6

    if-eqz v6, :cond_4

    iget-object v6, v3, La/e/b/h/d;->b:La/e/b/h/l/c;

    if-nez v6, :cond_2

    new-instance v6, La/e/b/h/l/c;

    invoke-direct {v6, v3, v5}, La/e/b/h/l/c;-><init>(La/e/b/h/d;I)V

    iput-object v6, v3, La/e/b/h/d;->b:La/e/b/h/l/c;

    :cond_2
    if-nez v2, :cond_3

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    :cond_3
    iget-object v5, v3, La/e/b/h/d;->b:La/e/b/h/l/c;

    invoke-virtual {v2, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    iget-object v5, v3, La/e/b/h/d;->d:La/e/b/h/l/k;

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_1
    invoke-virtual {v3}, La/e/b/h/d;->x()Z

    move-result v5

    if-eqz v5, :cond_7

    iget-object v5, v3, La/e/b/h/d;->c:La/e/b/h/l/c;

    if-nez v5, :cond_5

    new-instance v5, La/e/b/h/l/c;

    invoke-direct {v5, v3, v4}, La/e/b/h/l/c;-><init>(La/e/b/h/d;I)V

    iput-object v5, v3, La/e/b/h/d;->c:La/e/b/h/l/c;

    :cond_5
    if-nez v2, :cond_6

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    :cond_6
    iget-object v4, v3, La/e/b/h/d;->c:La/e/b/h/l/c;

    invoke-virtual {v2, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_7
    iget-object v4, v3, La/e/b/h/d;->e:La/e/b/h/l/m;

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_2
    instance-of v4, v3, La/e/b/h/h;

    if-eqz v4, :cond_0

    new-instance v4, La/e/b/h/l/j;

    invoke-direct {v4, v3}, La/e/b/h/l/j;-><init>(La/e/b/h/d;)V

    :goto_3
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_8
    if-eqz v2, :cond_9

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :cond_9
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_a

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/o;

    invoke-virtual {v2}, La/e/b/h/l/o;->f()V

    goto :goto_4

    :cond_a
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_c

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/o;

    iget-object v2, v1, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v3, p0, La/e/b/h/l/e;->d:La/e/b/h/e;

    if-ne v2, v3, :cond_b

    goto :goto_5

    :cond_b
    invoke-virtual {v1}, La/e/b/h/l/o;->d()V

    goto :goto_5

    .line 2
    :cond_c
    iget-object v0, p0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    sput v5, La/e/b/h/l/l;->c:I

    iget-object v0, p0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, p0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    invoke-virtual {p0, v0, v5, v1}, La/e/b/h/l/e;->e(La/e/b/h/l/o;ILjava/util/ArrayList;)V

    iget-object v0, p0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, p0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    invoke-virtual {p0, v0, v4, v1}, La/e/b/h/l/e;->e(La/e/b/h/l/o;ILjava/util/ArrayList;)V

    iput-boolean v5, p0, La/e/b/h/l/e;->b:Z

    return-void
.end method

.method public final d(La/e/b/h/e;I)I
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p2

    iget-object v3, v0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v3

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    move-wide v7, v4

    :goto_0
    if-ge v6, v3, :cond_e

    iget-object v9, v0, La/e/b/h/l/e;->h:Ljava/util/ArrayList;

    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, La/e/b/h/l/l;

    .line 1
    iget-object v10, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    instance-of v11, v10, La/e/b/h/l/c;

    if-eqz v11, :cond_0

    check-cast v10, La/e/b/h/l/c;

    iget v10, v10, La/e/b/h/l/o;->f:I

    if-eq v10, v2, :cond_2

    goto/16 :goto_6

    :cond_0
    if-nez v2, :cond_1

    instance-of v10, v10, La/e/b/h/l/k;

    if-nez v10, :cond_2

    goto/16 :goto_6

    :cond_1
    instance-of v10, v10, La/e/b/h/l/m;

    if-nez v10, :cond_2

    goto/16 :goto_6

    :cond_2
    if-nez v2, :cond_3

    iget-object v10, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_1

    :cond_3
    iget-object v10, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    :goto_1
    iget-object v10, v10, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    if-nez v2, :cond_4

    iget-object v11, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_2

    :cond_4
    iget-object v11, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    :goto_2
    iget-object v11, v11, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v12, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v12, v12, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v12, v12, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v12, v10}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v10

    iget-object v12, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v12, v12, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v12, v12, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v12, v11}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v11

    iget-object v12, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    invoke-virtual {v12}, La/e/b/h/l/o;->j()J

    move-result-wide v12

    if-eqz v10, :cond_b

    if-eqz v11, :cond_b

    iget-object v10, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v10, v10, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v9, v10, v4, v5}, La/e/b/h/l/l;->b(La/e/b/h/l/f;J)J

    move-result-wide v10

    iget-object v14, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v14, v14, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v9, v14, v4, v5}, La/e/b/h/l/l;->a(La/e/b/h/l/f;J)J

    move-result-wide v14

    sub-long/2addr v10, v12

    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    neg-int v5, v4

    int-to-long v0, v5

    cmp-long v0, v10, v0

    if-ltz v0, :cond_5

    int-to-long v0, v4

    add-long/2addr v10, v0

    :cond_5
    neg-long v0, v14

    sub-long/2addr v0, v12

    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    int-to-long v4, v4

    sub-long/2addr v0, v4

    cmp-long v14, v0, v4

    if-ltz v14, :cond_6

    sub-long/2addr v0, v4

    :cond_6
    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->b:La/e/b/h/d;

    if-eqz v4, :cond_a

    if-nez v2, :cond_7

    .line 2
    iget v4, v4, La/e/b/h/d;->b0:F

    goto :goto_3

    :cond_7
    const/4 v5, 0x1

    if-ne v2, v5, :cond_8

    iget v4, v4, La/e/b/h/d;->c0:F

    goto :goto_3

    :cond_8
    const/high16 v4, -0x40800000    # -1.0f

    :goto_3
    const/4 v5, 0x0

    cmpl-float v5, v4, v5

    const/high16 v14, 0x3f800000    # 1.0f

    if-lez v5, :cond_9

    long-to-float v0, v0

    div-float/2addr v0, v4

    long-to-float v1, v10

    sub-float v5, v14, v4

    div-float/2addr v1, v5

    add-float/2addr v1, v0

    float-to-long v0, v1

    goto :goto_4

    :cond_9
    const-wide/16 v0, 0x0

    :goto_4
    long-to-float v0, v0

    mul-float v1, v0, v4

    const/high16 v5, 0x3f000000    # 0.5f

    add-float/2addr v1, v5

    float-to-long v10, v1

    sub-float/2addr v14, v4

    mul-float/2addr v14, v0

    add-float/2addr v14, v5

    float-to-long v0, v14

    add-long/2addr v10, v12

    add-long/2addr v10, v0

    .line 3
    iget-object v0, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v1, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    int-to-long v4, v1

    add-long/2addr v4, v10

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->f:I

    int-to-long v0, v0

    sub-long/2addr v4, v0

    goto :goto_6

    :cond_a
    const/4 v0, 0x0

    .line 4
    throw v0

    :cond_b
    if-eqz v10, :cond_c

    .line 5
    iget-object v0, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v0, La/e/b/h/l/f;->f:I

    int-to-long v4, v1

    invoke-virtual {v9, v0, v4, v5}, La/e/b/h/l/l;->b(La/e/b/h/l/f;J)J

    move-result-wide v0

    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    int-to-long v4, v4

    add-long/2addr v4, v12

    goto :goto_5

    :cond_c
    iget-object v0, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    if-eqz v11, :cond_d

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v0, La/e/b/h/l/f;->f:I

    int-to-long v4, v1

    invoke-virtual {v9, v0, v4, v5}, La/e/b/h/l/l;->a(La/e/b/h/l/f;J)J

    move-result-wide v0

    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    neg-int v4, v4

    int-to-long v4, v4

    add-long/2addr v4, v12

    neg-long v0, v0

    :goto_5
    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v4

    goto :goto_6

    :cond_d
    iget-object v1, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    int-to-long v4, v1

    invoke-virtual {v0}, La/e/b/h/l/o;->j()J

    move-result-wide v0

    add-long/2addr v0, v4

    iget-object v4, v9, La/e/b/h/l/l;->a:La/e/b/h/l/o;

    iget-object v4, v4, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    int-to-long v4, v4

    sub-long v4, v0, v4

    .line 6
    :goto_6
    invoke-static {v7, v8, v4, v5}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v7

    add-int/lit8 v6, v6, 0x1

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-wide/16 v4, 0x0

    goto/16 :goto_0

    :cond_e
    long-to-int v0, v7

    return v0
.end method

.method public final e(La/e/b/h/l/o;ILjava/util/ArrayList;)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/e/b/h/l/o;",
            "I",
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/l;",
            ">;)V"
        }
    .end annotation

    iget-object v0, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/d;

    instance-of v2, v1, La/e/b/h/l/f;

    if-eqz v2, :cond_1

    move-object v4, v1

    check-cast v4, La/e/b/h/l/f;

    const/4 v6, 0x0

    iget-object v7, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    const/4 v9, 0x0

    move-object v3, p0

    move v5, p2

    move-object v8, p3

    invoke-virtual/range {v3 .. v9}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_0

    :cond_1
    instance-of v2, v1, La/e/b/h/l/o;

    if-eqz v2, :cond_0

    check-cast v1, La/e/b/h/l/o;

    iget-object v3, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    const/4 v5, 0x0

    iget-object v6, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    const/4 v8, 0x0

    move-object v2, p0

    move v4, p2

    move-object v7, p3

    invoke-virtual/range {v2 .. v8}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_0

    :cond_2
    iget-object v0, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/e/b/h/l/d;

    instance-of v2, v1, La/e/b/h/l/f;

    if-eqz v2, :cond_4

    move-object v4, v1

    check-cast v4, La/e/b/h/l/f;

    const/4 v6, 0x1

    iget-object v7, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    const/4 v9, 0x0

    move-object v3, p0

    move v5, p2

    move-object v8, p3

    invoke-virtual/range {v3 .. v9}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_1

    :cond_4
    instance-of v2, v1, La/e/b/h/l/o;

    if-eqz v2, :cond_3

    check-cast v1, La/e/b/h/l/o;

    iget-object v3, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    const/4 v5, 0x1

    iget-object v6, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    const/4 v8, 0x0

    move-object v2, p0

    move v4, p2

    move-object v7, p3

    invoke-virtual/range {v2 .. v8}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_1

    :cond_5
    const/4 v0, 0x1

    if-ne p2, v0, :cond_7

    check-cast p1, La/e/b/h/l/m;

    iget-object p1, p1, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_6
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/d;

    instance-of v1, v0, La/e/b/h/l/f;

    if-eqz v1, :cond_6

    move-object v3, v0

    check-cast v3, La/e/b/h/l/f;

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v8, 0x0

    move-object v2, p0

    move v4, p2

    move-object v7, p3

    invoke-virtual/range {v2 .. v8}, La/e/b/h/l/e;->a(La/e/b/h/l/f;IILa/e/b/h/l/f;Ljava/util/ArrayList;La/e/b/h/l/l;)V

    goto :goto_2

    :cond_7
    return-void
.end method

.method public final f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V
    .locals 1

    iget-object v0, p0, La/e/b/h/l/e;->g:La/e/b/h/l/b$a;

    iput-object p2, v0, La/e/b/h/l/b$a;->a:La/e/b/h/d$a;

    iput-object p4, v0, La/e/b/h/l/b$a;->b:La/e/b/h/d$a;

    iput p3, v0, La/e/b/h/l/b$a;->c:I

    iput p5, v0, La/e/b/h/l/b$a;->d:I

    iget-object p2, p0, La/e/b/h/l/e;->f:La/e/b/h/l/b$b;

    check-cast p2, Landroidx/constraintlayout/widget/ConstraintLayout$b;

    invoke-virtual {p2, p1, v0}, Landroidx/constraintlayout/widget/ConstraintLayout$b;->b(La/e/b/h/d;La/e/b/h/l/b$a;)V

    iget-object p2, p0, La/e/b/h/l/e;->g:La/e/b/h/l/b$a;

    iget p2, p2, La/e/b/h/l/b$a;->e:I

    invoke-virtual {p1, p2}, La/e/b/h/d;->M(I)V

    iget-object p2, p0, La/e/b/h/l/e;->g:La/e/b/h/l/b$a;

    iget p2, p2, La/e/b/h/l/b$a;->f:I

    invoke-virtual {p1, p2}, La/e/b/h/d;->H(I)V

    iget-object p2, p0, La/e/b/h/l/e;->g:La/e/b/h/l/b$a;

    iget-boolean p3, p2, La/e/b/h/l/b$a;->h:Z

    .line 1
    iput-boolean p3, p1, La/e/b/h/d;->A:Z

    .line 2
    iget p2, p2, La/e/b/h/l/b$a;->g:I

    invoke-virtual {p1, p2}, La/e/b/h/d;->E(I)V

    return-void
.end method

.method public g()V
    .locals 14

    sget-object v6, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v7, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    sget-object v8, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    iget-object v0, p0, La/e/b/h/l/e;->a:La/e/b/h/e;

    iget-object v0, v0, La/e/b/h/k;->o0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :cond_0
    :goto_0
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_a

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v10, v0

    check-cast v10, La/e/b/h/d;

    iget-boolean v0, v10, La/e/b/h/d;->a:Z

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, v10, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x0

    aget-object v11, v0, v1

    const/4 v12, 0x1

    aget-object v13, v0, v12

    iget v0, v10, La/e/b/h/d;->n:I

    iget v2, v10, La/e/b/h/d;->o:I

    if-eq v11, v8, :cond_3

    if-ne v11, v7, :cond_2

    if-ne v0, v12, :cond_2

    goto :goto_1

    :cond_2
    move v0, v1

    goto :goto_2

    :cond_3
    :goto_1
    move v0, v12

    :goto_2
    if-eq v13, v8, :cond_4

    if-ne v13, v7, :cond_5

    if-ne v2, v12, :cond_5

    :cond_4
    move v1, v12

    :cond_5
    iget-object v2, v10, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v2, v2, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v3, v2, La/e/b/h/l/f;->j:Z

    iget-object v4, v10, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v4, v4, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v5, v4, La/e/b/h/l/f;->j:Z

    if-eqz v3, :cond_6

    if-eqz v5, :cond_6

    iget v3, v2, La/e/b/h/l/f;->g:I

    iget v5, v4, La/e/b/h/l/f;->g:I

    move-object v0, p0

    move-object v1, v10

    move-object v2, v6

    move-object v4, v6

    invoke-virtual/range {v0 .. v5}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    :goto_3
    iput-boolean v12, v10, La/e/b/h/d;->a:Z

    goto :goto_5

    :cond_6
    if-eqz v3, :cond_8

    if-eqz v1, :cond_8

    iget-object v0, v10, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v3, v0, La/e/b/h/l/f;->g:I

    iget-object v0, v10, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v5, v0, La/e/b/h/l/f;->g:I

    move-object v0, p0

    move-object v1, v10

    move-object v2, v6

    move-object v4, v8

    invoke-virtual/range {v0 .. v5}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v0, v10, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v10}, La/e/b/h/d;->l()I

    move-result v1

    if-ne v13, v7, :cond_7

    :goto_4
    iput v1, v0, La/e/b/h/l/g;->m:I

    goto :goto_5

    :cond_7
    invoke-virtual {v0, v1}, La/e/b/h/l/g;->c(I)V

    goto :goto_3

    :cond_8
    if-eqz v5, :cond_9

    if-eqz v0, :cond_9

    iget-object v0, v10, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v3, v0, La/e/b/h/l/f;->g:I

    iget-object v0, v10, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v5, v0, La/e/b/h/l/f;->g:I

    move-object v0, p0

    move-object v1, v10

    move-object v2, v8

    move-object v4, v6

    invoke-virtual/range {v0 .. v5}, La/e/b/h/l/e;->f(La/e/b/h/d;La/e/b/h/d$a;ILa/e/b/h/d$a;I)V

    iget-object v0, v10, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v10}, La/e/b/h/d;->r()I

    move-result v1

    if-ne v11, v7, :cond_7

    goto :goto_4

    :cond_9
    :goto_5
    iget-boolean v0, v10, La/e/b/h/d;->a:Z

    if-eqz v0, :cond_0

    iget-object v0, v10, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    if-eqz v0, :cond_0

    .line 1
    iget v1, v10, La/e/b/h/d;->Y:I

    .line 2
    invoke-virtual {v0, v1}, La/e/b/h/l/g;->c(I)V

    goto/16 :goto_0

    :cond_a
    return-void
.end method
