.class public La/e/b/d;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/d$a;
    }
.end annotation


# static fields
.field public static r:Z = false

.field public static s:I = 0x3e8

.field public static t:J


# instance fields
.field public a:Z

.field public b:I

.field public c:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "La/e/b/g;",
            ">;"
        }
    .end annotation
.end field

.field public d:La/e/b/d$a;

.field public e:I

.field public f:I

.field public g:[La/e/b/b;

.field public h:Z

.field public i:Z

.field public j:[Z

.field public k:I

.field public l:I

.field public m:I

.field public final n:La/e/b/c;

.field public o:[La/e/b/g;

.field public p:I

.field public q:La/e/b/d$a;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/d;->a:Z

    iput v0, p0, La/e/b/d;->b:I

    const/4 v1, 0x0

    iput-object v1, p0, La/e/b/d;->c:Ljava/util/HashMap;

    const/16 v2, 0x20

    iput v2, p0, La/e/b/d;->e:I

    iput v2, p0, La/e/b/d;->f:I

    iput-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    iput-boolean v0, p0, La/e/b/d;->h:Z

    iput-boolean v0, p0, La/e/b/d;->i:Z

    new-array v1, v2, [Z

    iput-object v1, p0, La/e/b/d;->j:[Z

    const/4 v1, 0x1

    iput v1, p0, La/e/b/d;->k:I

    iput v0, p0, La/e/b/d;->l:I

    iput v2, p0, La/e/b/d;->m:I

    sget v1, La/e/b/d;->s:I

    new-array v1, v1, [La/e/b/g;

    iput-object v1, p0, La/e/b/d;->o:[La/e/b/g;

    iput v0, p0, La/e/b/d;->p:I

    new-array v0, v2, [La/e/b/b;

    iput-object v0, p0, La/e/b/d;->g:[La/e/b/b;

    invoke-virtual {p0}, La/e/b/d;->t()V

    new-instance v0, La/e/b/c;

    invoke-direct {v0}, La/e/b/c;-><init>()V

    iput-object v0, p0, La/e/b/d;->n:La/e/b/c;

    new-instance v1, La/e/b/f;

    invoke-direct {v1, v0}, La/e/b/f;-><init>(La/e/b/c;)V

    iput-object v1, p0, La/e/b/d;->d:La/e/b/d$a;

    new-instance v0, La/e/b/b;

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    invoke-direct {v0, v1}, La/e/b/b;-><init>(La/e/b/c;)V

    iput-object v0, p0, La/e/b/d;->q:La/e/b/d$a;

    return-void
.end method


# virtual methods
.method public final a(La/e/b/g$a;Ljava/lang/String;)La/e/b/g;
    .locals 2

    iget-object p2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object p2, p2, La/e/b/c;->c:La/e/b/e;

    invoke-virtual {p2}, La/e/b/e;->a()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, La/e/b/g;

    if-nez p2, :cond_0

    new-instance p2, La/e/b/g;

    invoke-direct {p2, p1}, La/e/b/g;-><init>(La/e/b/g$a;)V

    goto :goto_0

    .line 1
    :cond_0
    invoke-virtual {p2}, La/e/b/g;->c()V

    .line 2
    :goto_0
    iput-object p1, p2, La/e/b/g;->j:La/e/b/g$a;

    .line 3
    iget p1, p0, La/e/b/d;->p:I

    sget v0, La/e/b/d;->s:I

    if-lt p1, v0, :cond_1

    mul-int/lit8 v0, v0, 0x2

    sput v0, La/e/b/d;->s:I

    iget-object p1, p0, La/e/b/d;->o:[La/e/b/g;

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [La/e/b/g;

    iput-object p1, p0, La/e/b/d;->o:[La/e/b/g;

    :cond_1
    iget-object p1, p0, La/e/b/d;->o:[La/e/b/g;

    iget v0, p0, La/e/b/d;->p:I

    add-int/lit8 v1, v0, 0x1

    iput v1, p0, La/e/b/d;->p:I

    aput-object p2, p1, v0

    return-object p2
.end method

.method public b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V
    .locals 6

    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    const/high16 v1, 0x3f800000    # 1.0f

    if-ne p2, p5, :cond_0

    .line 1
    iget-object p3, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p3, p1, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p6, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    const/high16 p3, -0x40000000    # -2.0f

    invoke-interface {p1, p2, p3}, La/e/b/b$a;->j(La/e/b/g;F)V

    goto :goto_2

    :cond_0
    const/high16 v2, 0x3f000000    # 0.5f

    cmpl-float v2, p4, v2

    const/high16 v3, -0x40800000    # -1.0f

    if-nez v2, :cond_2

    iget-object p4, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p4, p1, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p2, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p5, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p6, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    if-gtz p3, :cond_1

    if-lez p7, :cond_6

    :cond_1
    neg-int p1, p3

    add-int/2addr p1, p7

    goto :goto_0

    :cond_2
    const/4 v2, 0x0

    cmpg-float v2, p4, v2

    if-gtz v2, :cond_3

    iget-object p4, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p4, p1, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p2, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    int-to-float p1, p3

    goto :goto_1

    :cond_3
    cmpl-float v2, p4, v1

    if-ltz v2, :cond_4

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p6, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p5, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    neg-int p1, p7

    :goto_0
    int-to-float p1, p1

    :goto_1
    iput p1, v0, La/e/b/b;->b:F

    goto :goto_2

    :cond_4
    iget-object v2, v0, La/e/b/b;->e:La/e/b/b$a;

    sub-float v4, v1, p4

    mul-float v5, v4, v1

    invoke-interface {v2, p1, v5}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    mul-float v2, v4, v3

    invoke-interface {p1, p2, v2}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    mul-float/2addr v3, p4

    invoke-interface {p1, p5, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    mul-float/2addr v1, p4

    invoke-interface {p1, p6, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    if-gtz p3, :cond_5

    if-lez p7, :cond_6

    :cond_5
    neg-int p1, p3

    int-to-float p1, p1

    mul-float/2addr p1, v4

    int-to-float p2, p7

    mul-float/2addr p2, p4

    add-float/2addr p2, p1

    iput p2, v0, La/e/b/b;->b:F

    :cond_6
    :goto_2
    const/16 p1, 0x8

    if-eq p8, p1, :cond_7

    .line 2
    invoke-virtual {v0, p0, p8}, La/e/b/b;->c(La/e/b/d;I)La/e/b/b;

    :cond_7
    invoke-virtual {p0, v0}, La/e/b/d;->c(La/e/b/b;)V

    return-void
.end method

.method public c(La/e/b/b;)V
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    sget-object v2, La/e/b/g$a;->b:La/e/b/g$a;

    iget v3, v0, La/e/b/d;->l:I

    const/4 v4, 0x1

    add-int/2addr v3, v4

    iget v5, v0, La/e/b/d;->m:I

    if-ge v3, v5, :cond_0

    iget v3, v0, La/e/b/d;->k:I

    add-int/2addr v3, v4

    iget v5, v0, La/e/b/d;->f:I

    if-lt v3, v5, :cond_1

    :cond_0
    invoke-virtual/range {p0 .. p0}, La/e/b/d;->p()V

    :cond_1
    iget-boolean v3, v1, La/e/b/b;->f:Z

    if-nez v3, :cond_24

    .line 1
    iget-object v3, v0, La/e/b/d;->g:[La/e/b/b;

    array-length v3, v3

    const/4 v6, -0x1

    if-nez v3, :cond_2

    goto/16 :goto_4

    :cond_2
    const/4 v3, 0x0

    :goto_0
    if-nez v3, :cond_c

    iget-object v7, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v7}, La/e/b/b$a;->k()I

    move-result v7

    const/4 v8, 0x0

    :goto_1
    if-ge v8, v7, :cond_5

    iget-object v9, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v9, v8}, La/e/b/b$a;->d(I)La/e/b/g;

    move-result-object v9

    iget v10, v9, La/e/b/g;->d:I

    if-ne v10, v6, :cond_3

    iget-boolean v10, v9, La/e/b/g;->g:Z

    if-nez v10, :cond_3

    iget-boolean v10, v9, La/e/b/g;->n:Z

    if-eqz v10, :cond_4

    :cond_3
    iget-object v10, v1, La/e/b/b;->d:Ljava/util/ArrayList;

    invoke-virtual {v10, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_4
    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_5
    iget-object v7, v1, La/e/b/b;->d:Ljava/util/ArrayList;

    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v7

    if-lez v7, :cond_b

    const/4 v8, 0x0

    :goto_2
    if-ge v8, v7, :cond_a

    iget-object v9, v1, La/e/b/b;->d:Ljava/util/ArrayList;

    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, La/e/b/g;

    iget-boolean v10, v9, La/e/b/g;->g:Z

    if-eqz v10, :cond_6

    invoke-virtual {v1, v0, v9, v4}, La/e/b/b;->k(La/e/b/d;La/e/b/g;Z)V

    goto :goto_3

    :cond_6
    iget-boolean v10, v9, La/e/b/g;->n:Z

    if-eqz v10, :cond_8

    if-nez v10, :cond_7

    goto :goto_3

    .line 2
    :cond_7
    iget-object v10, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v10, v9}, La/e/b/b$a;->e(La/e/b/g;)F

    move-result v10

    iget v11, v1, La/e/b/b;->b:F

    iget v12, v9, La/e/b/g;->p:F

    mul-float/2addr v12, v10

    add-float/2addr v12, v11

    iput v12, v1, La/e/b/b;->b:F

    iget-object v11, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v11, v9, v4}, La/e/b/b$a;->b(La/e/b/g;Z)F

    invoke-virtual {v9, v1}, La/e/b/g;->b(La/e/b/b;)V

    iget-object v11, v1, La/e/b/b;->e:La/e/b/b$a;

    iget-object v12, v0, La/e/b/d;->n:La/e/b/c;

    iget-object v12, v12, La/e/b/c;->d:[La/e/b/g;

    iget v9, v9, La/e/b/g;->o:I

    aget-object v9, v12, v9

    invoke-interface {v11, v9, v10, v4}, La/e/b/b$a;->c(La/e/b/g;FZ)V

    iget-object v9, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v9}, La/e/b/b$a;->k()I

    move-result v9

    if-nez v9, :cond_9

    iput-boolean v4, v1, La/e/b/b;->f:Z

    iput-boolean v4, v0, La/e/b/d;->a:Z

    goto :goto_3

    .line 3
    :cond_8
    iget-object v10, v0, La/e/b/d;->g:[La/e/b/b;

    iget v9, v9, La/e/b/g;->d:I

    aget-object v9, v10, v9

    invoke-virtual {v1, v0, v9, v4}, La/e/b/b;->l(La/e/b/d;La/e/b/b;Z)V

    :cond_9
    :goto_3
    add-int/lit8 v8, v8, 0x1

    goto :goto_2

    :cond_a
    iget-object v7, v1, La/e/b/b;->d:Ljava/util/ArrayList;

    invoke-virtual {v7}, Ljava/util/ArrayList;->clear()V

    goto/16 :goto_0

    :cond_b
    move v3, v4

    goto/16 :goto_0

    :cond_c
    iget-object v3, v1, La/e/b/b;->a:La/e/b/g;

    if-eqz v3, :cond_d

    iget-object v3, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v3}, La/e/b/b$a;->k()I

    move-result v3

    if-nez v3, :cond_d

    iput-boolean v4, v1, La/e/b/b;->f:Z

    iput-boolean v4, v0, La/e/b/d;->a:Z

    .line 4
    :cond_d
    :goto_4
    invoke-virtual/range {p1 .. p1}, La/e/b/b;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_e

    return-void

    .line 5
    :cond_e
    iget v3, v1, La/e/b/b;->b:F

    const/4 v7, 0x0

    cmpg-float v8, v3, v7

    if-gez v8, :cond_f

    const/high16 v8, -0x40800000    # -1.0f

    mul-float/2addr v3, v8

    iput v3, v1, La/e/b/b;->b:F

    iget-object v3, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v3}, La/e/b/b$a;->i()V

    .line 6
    :cond_f
    iget-object v3, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v3}, La/e/b/b$a;->k()I

    move-result v3

    move v12, v7

    move v14, v12

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    :goto_5
    if-ge v9, v3, :cond_16

    iget-object v5, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v5, v9}, La/e/b/b$a;->a(I)F

    move-result v5

    iget-object v6, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v6, v9}, La/e/b/b$a;->d(I)La/e/b/g;

    move-result-object v6

    iget-object v8, v6, La/e/b/g;->j:La/e/b/g$a;

    if-ne v8, v2, :cond_12

    if-nez v10, :cond_10

    goto :goto_6

    :cond_10
    cmpl-float v8, v12, v5

    if-lez v8, :cond_11

    :goto_6
    invoke-virtual {v1, v6}, La/e/b/b;->h(La/e/b/g;)Z

    move-result v8

    move v13, v8

    goto :goto_7

    :cond_11
    if-nez v13, :cond_15

    invoke-virtual {v1, v6}, La/e/b/b;->h(La/e/b/g;)Z

    move-result v8

    if-eqz v8, :cond_15

    move v13, v4

    :goto_7
    move v12, v5

    move-object v10, v6

    goto :goto_a

    :cond_12
    if-nez v10, :cond_15

    cmpg-float v8, v5, v7

    if-gez v8, :cond_15

    if-nez v11, :cond_13

    goto :goto_8

    :cond_13
    cmpl-float v8, v14, v5

    if-lez v8, :cond_14

    :goto_8
    invoke-virtual {v1, v6}, La/e/b/b;->h(La/e/b/g;)Z

    move-result v8

    move v15, v8

    goto :goto_9

    :cond_14
    if-nez v15, :cond_15

    invoke-virtual {v1, v6}, La/e/b/b;->h(La/e/b/g;)Z

    move-result v8

    if-eqz v8, :cond_15

    move v15, v4

    :goto_9
    move v14, v5

    move-object v11, v6

    :cond_15
    :goto_a
    add-int/lit8 v9, v9, 0x1

    const/4 v6, -0x1

    goto :goto_5

    :cond_16
    if-eqz v10, :cond_17

    goto :goto_b

    :cond_17
    move-object v10, v11

    :goto_b
    if-nez v10, :cond_18

    move v3, v4

    goto :goto_c

    .line 7
    :cond_18
    invoke-virtual {v1, v10}, La/e/b/b;->j(La/e/b/g;)V

    const/4 v3, 0x0

    :goto_c
    iget-object v5, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v5}, La/e/b/b$a;->k()I

    move-result v5

    if-nez v5, :cond_19

    iput-boolean v4, v1, La/e/b/b;->f:Z

    :cond_19
    if-eqz v3, :cond_20

    .line 8
    iget v3, v0, La/e/b/d;->k:I

    add-int/2addr v3, v4

    iget v5, v0, La/e/b/d;->f:I

    if-lt v3, v5, :cond_1a

    invoke-virtual/range {p0 .. p0}, La/e/b/d;->p()V

    :cond_1a
    sget-object v3, La/e/b/g$a;->d:La/e/b/g$a;

    const/4 v5, 0x0

    invoke-virtual {v0, v3, v5}, La/e/b/d;->a(La/e/b/g$a;Ljava/lang/String;)La/e/b/g;

    move-result-object v3

    iget v5, v0, La/e/b/d;->b:I

    add-int/2addr v5, v4

    iput v5, v0, La/e/b/d;->b:I

    iget v6, v0, La/e/b/d;->k:I

    add-int/2addr v6, v4

    iput v6, v0, La/e/b/d;->k:I

    iput v5, v3, La/e/b/g;->c:I

    iget-object v6, v0, La/e/b/d;->n:La/e/b/c;

    iget-object v6, v6, La/e/b/c;->d:[La/e/b/g;

    aput-object v3, v6, v5

    .line 9
    iput-object v3, v1, La/e/b/b;->a:La/e/b/g;

    iget v5, v0, La/e/b/d;->l:I

    invoke-virtual/range {p0 .. p1}, La/e/b/d;->i(La/e/b/b;)V

    iget v6, v0, La/e/b/d;->l:I

    add-int/2addr v5, v4

    if-ne v6, v5, :cond_20

    iget-object v5, v0, La/e/b/d;->q:La/e/b/d$a;

    check-cast v5, La/e/b/b;

    if-eqz v5, :cond_1f

    const/4 v6, 0x0

    .line 10
    iput-object v6, v5, La/e/b/b;->a:La/e/b/g;

    iget-object v6, v5, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v6}, La/e/b/b$a;->clear()V

    const/4 v6, 0x0

    :goto_d
    iget-object v8, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v8}, La/e/b/b$a;->k()I

    move-result v8

    if-ge v6, v8, :cond_1b

    iget-object v8, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v8, v6}, La/e/b/b$a;->d(I)La/e/b/g;

    move-result-object v8

    iget-object v9, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v9, v6}, La/e/b/b$a;->a(I)F

    move-result v9

    iget-object v10, v5, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v10, v8, v9, v4}, La/e/b/b$a;->c(La/e/b/g;FZ)V

    add-int/lit8 v6, v6, 0x1

    goto :goto_d

    .line 11
    :cond_1b
    iget-object v5, v0, La/e/b/d;->q:La/e/b/d$a;

    invoke-virtual {v0, v5}, La/e/b/d;->s(La/e/b/d$a;)I

    iget v5, v3, La/e/b/g;->d:I

    const/4 v6, -0x1

    if-ne v5, v6, :cond_1e

    iget-object v5, v1, La/e/b/b;->a:La/e/b/g;

    if-ne v5, v3, :cond_1c

    const/4 v5, 0x0

    .line 12
    invoke-virtual {v1, v5, v3}, La/e/b/b;->i([ZLa/e/b/g;)La/e/b/g;

    move-result-object v3

    if-eqz v3, :cond_1c

    .line 13
    invoke-virtual {v1, v3}, La/e/b/b;->j(La/e/b/g;)V

    :cond_1c
    iget-boolean v3, v1, La/e/b/b;->f:Z

    if-nez v3, :cond_1d

    iget-object v3, v1, La/e/b/b;->a:La/e/b/g;

    invoke-virtual {v3, v0, v1}, La/e/b/g;->e(La/e/b/d;La/e/b/b;)V

    :cond_1d
    iget-object v3, v0, La/e/b/d;->n:La/e/b/c;

    iget-object v3, v3, La/e/b/c;->b:La/e/b/e;

    invoke-virtual {v3, v1}, La/e/b/e;->b(Ljava/lang/Object;)Z

    iget v3, v0, La/e/b/d;->l:I

    sub-int/2addr v3, v4

    iput v3, v0, La/e/b/d;->l:I

    :cond_1e
    move v3, v4

    goto :goto_e

    :cond_1f
    const/4 v3, 0x0

    .line 14
    throw v3

    :cond_20
    const/4 v3, 0x0

    .line 15
    :goto_e
    iget-object v5, v1, La/e/b/b;->a:La/e/b/g;

    if-eqz v5, :cond_21

    iget-object v5, v5, La/e/b/g;->j:La/e/b/g$a;

    if-eq v5, v2, :cond_22

    iget v2, v1, La/e/b/b;->b:F

    cmpg-float v2, v2, v7

    if-ltz v2, :cond_21

    goto :goto_f

    :cond_21
    const/4 v4, 0x0

    :cond_22
    :goto_f
    if-nez v4, :cond_23

    return-void

    :cond_23
    move v5, v3

    goto :goto_10

    :cond_24
    const/4 v5, 0x0

    :goto_10
    if-nez v5, :cond_25

    .line 16
    invoke-virtual/range {p0 .. p1}, La/e/b/d;->i(La/e/b/b;)V

    :cond_25
    return-void
.end method

.method public d(La/e/b/g;La/e/b/g;II)La/e/b/b;
    .locals 4

    const/16 v0, 0x8

    if-ne p4, v0, :cond_0

    iget-boolean v1, p2, La/e/b/g;->g:Z

    if-eqz v1, :cond_0

    iget v1, p1, La/e/b/g;->d:I

    const/4 v2, -0x1

    if-ne v1, v2, :cond_0

    iget p2, p2, La/e/b/g;->f:F

    int-to-float p3, p3

    add-float/2addr p2, p3

    invoke-virtual {p1, p0, p2}, La/e/b/g;->d(La/e/b/d;F)V

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz p3, :cond_2

    if-gez p3, :cond_1

    mul-int/lit8 p3, p3, -0x1

    const/4 v2, 0x1

    :cond_1
    int-to-float p3, p3

    .line 1
    iput p3, v1, La/e/b/b;->b:F

    :cond_2
    const/high16 p3, -0x40800000    # -1.0f

    const/high16 v3, 0x3f800000    # 1.0f

    if-nez v2, :cond_3

    iget-object v2, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v2, p1, p3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p2, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    goto :goto_0

    :cond_3
    iget-object v2, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v2, p1, v3}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p1, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, p2, p3}, La/e/b/b$a;->j(La/e/b/g;F)V

    :goto_0
    if-eq p4, v0, :cond_4

    .line 2
    invoke-virtual {v1, p0, p4}, La/e/b/b;->c(La/e/b/d;I)La/e/b/b;

    :cond_4
    invoke-virtual {p0, v1}, La/e/b/d;->c(La/e/b/b;)V

    return-object v1
.end method

.method public e(La/e/b/g;I)V
    .locals 5

    iget v0, p1, La/e/b/g;->d:I

    const/4 v1, -0x1

    const/4 v2, 0x1

    if-ne v0, v1, :cond_2

    int-to-float p2, p2

    invoke-virtual {p1, p0, p2}, La/e/b/g;->d(La/e/b/d;F)V

    const/4 v0, 0x0

    :goto_0
    iget v1, p0, La/e/b/d;->b:I

    add-int/2addr v1, v2

    if-ge v0, v1, :cond_1

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v1, v1, La/e/b/c;->d:[La/e/b/g;

    aget-object v1, v1, v0

    if-eqz v1, :cond_0

    iget-boolean v3, v1, La/e/b/g;->n:Z

    if-eqz v3, :cond_0

    iget v3, v1, La/e/b/g;->o:I

    iget v4, p1, La/e/b/g;->c:I

    if-ne v3, v4, :cond_0

    iget v3, v1, La/e/b/g;->p:F

    add-float/2addr v3, p2

    invoke-virtual {v1, p0, v3}, La/e/b/g;->d(La/e/b/d;F)V

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void

    :cond_2
    if-eq v0, v1, :cond_6

    iget-object v3, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v0, v3, v0

    iget-boolean v3, v0, La/e/b/b;->f:Z

    if-eqz v3, :cond_3

    :goto_1
    int-to-float p1, p2

    iput p1, v0, La/e/b/b;->b:F

    goto :goto_4

    :cond_3
    iget-object v3, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v3}, La/e/b/b$a;->k()I

    move-result v3

    if-nez v3, :cond_4

    iput-boolean v2, v0, La/e/b/b;->f:Z

    goto :goto_1

    :cond_4
    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    if-gez p2, :cond_5

    mul-int/2addr p2, v1

    int-to-float p2, p2

    .line 1
    iput p2, v0, La/e/b/b;->b:F

    iget-object p2, v0, La/e/b/b;->e:La/e/b/b$a;

    const/high16 v1, 0x3f800000    # 1.0f

    goto :goto_2

    :cond_5
    int-to-float p2, p2

    iput p2, v0, La/e/b/b;->b:F

    iget-object p2, v0, La/e/b/b;->e:La/e/b/b$a;

    const/high16 v1, -0x40800000    # -1.0f

    :goto_2
    invoke-interface {p2, p1, v1}, La/e/b/b$a;->j(La/e/b/g;F)V

    goto :goto_3

    .line 2
    :cond_6
    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    .line 3
    iput-object p1, v0, La/e/b/b;->a:La/e/b/g;

    int-to-float p2, p2

    iput p2, p1, La/e/b/g;->f:F

    iput p2, v0, La/e/b/b;->b:F

    iput-boolean v2, v0, La/e/b/b;->f:Z

    .line 4
    :goto_3
    invoke-virtual {p0, v0}, La/e/b/d;->c(La/e/b/b;)V

    :goto_4
    return-void
.end method

.method public f(La/e/b/g;La/e/b/g;II)V
    .locals 3

    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    invoke-virtual {p0}, La/e/b/d;->n()La/e/b/g;

    move-result-object v1

    const/4 v2, 0x0

    iput v2, v1, La/e/b/g;->e:I

    invoke-virtual {v0, p1, p2, v1, p3}, La/e/b/b;->e(La/e/b/g;La/e/b/g;La/e/b/g;I)La/e/b/b;

    const/16 p1, 0x8

    if-eq p4, p1, :cond_0

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, v1}, La/e/b/b$a;->e(La/e/b/g;)F

    move-result p1

    const/high16 p2, -0x40800000    # -1.0f

    mul-float/2addr p1, p2

    float-to-int p1, p1

    const/4 p2, 0x0

    .line 1
    invoke-virtual {p0, p4, p2}, La/e/b/d;->k(ILjava/lang/String;)La/e/b/g;

    move-result-object p2

    .line 2
    iget-object p3, v0, La/e/b/b;->e:La/e/b/b$a;

    int-to-float p1, p1

    invoke-interface {p3, p2, p1}, La/e/b/b$a;->j(La/e/b/g;F)V

    .line 3
    :cond_0
    invoke-virtual {p0, v0}, La/e/b/d;->c(La/e/b/b;)V

    return-void
.end method

.method public g(La/e/b/g;La/e/b/g;II)V
    .locals 3

    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    invoke-virtual {p0}, La/e/b/d;->n()La/e/b/g;

    move-result-object v1

    const/4 v2, 0x0

    iput v2, v1, La/e/b/g;->e:I

    invoke-virtual {v0, p1, p2, v1, p3}, La/e/b/b;->f(La/e/b/g;La/e/b/g;La/e/b/g;I)La/e/b/b;

    const/16 p1, 0x8

    if-eq p4, p1, :cond_0

    iget-object p1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p1, v1}, La/e/b/b$a;->e(La/e/b/g;)F

    move-result p1

    const/high16 p2, -0x40800000    # -1.0f

    mul-float/2addr p1, p2

    float-to-int p1, p1

    const/4 p2, 0x0

    .line 1
    invoke-virtual {p0, p4, p2}, La/e/b/d;->k(ILjava/lang/String;)La/e/b/g;

    move-result-object p2

    .line 2
    iget-object p3, v0, La/e/b/b;->e:La/e/b/b$a;

    int-to-float p1, p1

    invoke-interface {p3, p2, p1}, La/e/b/b$a;->j(La/e/b/g;F)V

    .line 3
    :cond_0
    invoke-virtual {p0, v0}, La/e/b/d;->c(La/e/b/b;)V

    return-void
.end method

.method public h(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;FI)V
    .locals 7

    invoke-virtual {p0}, La/e/b/d;->m()La/e/b/b;

    move-result-object v6

    move-object v0, v6

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move v5, p5

    invoke-virtual/range {v0 .. v5}, La/e/b/b;->d(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;F)La/e/b/b;

    const/16 p1, 0x8

    if-eq p6, p1, :cond_0

    invoke-virtual {v6, p0, p6}, La/e/b/b;->c(La/e/b/d;I)La/e/b/b;

    :cond_0
    invoke-virtual {p0, v6}, La/e/b/d;->c(La/e/b/b;)V

    return-void
.end method

.method public final i(La/e/b/b;)V
    .locals 7

    iget-boolean v0, p1, La/e/b/b;->f:Z

    if-eqz v0, :cond_0

    iget-object v0, p1, La/e/b/b;->a:La/e/b/g;

    iget p1, p1, La/e/b/b;->b:F

    invoke-virtual {v0, p0, p1}, La/e/b/g;->d(La/e/b/d;F)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/e/b/d;->g:[La/e/b/b;

    iget v1, p0, La/e/b/d;->l:I

    aput-object p1, v0, v1

    iget-object v0, p1, La/e/b/b;->a:La/e/b/g;

    iput v1, v0, La/e/b/g;->d:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, La/e/b/d;->l:I

    invoke-virtual {v0, p0, p1}, La/e/b/g;->e(La/e/b/d;La/e/b/b;)V

    :goto_0
    iget-boolean p1, p0, La/e/b/d;->a:Z

    if-eqz p1, :cond_7

    const/4 p1, 0x0

    move v0, p1

    :goto_1
    iget v1, p0, La/e/b/d;->l:I

    if-ge v0, v1, :cond_6

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v1, v1, v0

    if-nez v1, :cond_1

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "WTF"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    :cond_1
    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v2, v1, v0

    if-eqz v2, :cond_5

    aget-object v2, v1, v0

    iget-boolean v2, v2, La/e/b/b;->f:Z

    if-eqz v2, :cond_5

    aget-object v1, v1, v0

    iget-object v2, v1, La/e/b/b;->a:La/e/b/g;

    iget v3, v1, La/e/b/b;->b:F

    invoke-virtual {v2, p0, v3}, La/e/b/g;->d(La/e/b/d;F)V

    iget-object v2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v2, v2, La/e/b/c;->b:La/e/b/e;

    invoke-virtual {v2, v1}, La/e/b/e;->b(Ljava/lang/Object;)Z

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    const/4 v2, 0x0

    aput-object v2, v1, v0

    add-int/lit8 v1, v0, 0x1

    move v3, v1

    :goto_2
    iget v4, p0, La/e/b/d;->l:I

    if-ge v1, v4, :cond_3

    iget-object v3, p0, La/e/b/d;->g:[La/e/b/b;

    add-int/lit8 v4, v1, -0x1

    aget-object v5, v3, v1

    aput-object v5, v3, v4

    aget-object v5, v3, v4

    iget-object v5, v5, La/e/b/b;->a:La/e/b/g;

    iget v5, v5, La/e/b/g;->d:I

    if-ne v5, v1, :cond_2

    aget-object v3, v3, v4

    iget-object v3, v3, La/e/b/b;->a:La/e/b/g;

    iput v4, v3, La/e/b/g;->d:I

    :cond_2
    add-int/lit8 v3, v1, 0x1

    move v6, v3

    move v3, v1

    move v1, v6

    goto :goto_2

    :cond_3
    if-ge v3, v4, :cond_4

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    aput-object v2, v1, v3

    :cond_4
    iget v1, p0, La/e/b/d;->l:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p0, La/e/b/d;->l:I

    add-int/lit8 v0, v0, -0x1

    :cond_5
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_6
    iput-boolean p1, p0, La/e/b/d;->a:Z

    :cond_7
    return-void
.end method

.method public final j()V
    .locals 3

    const/4 v0, 0x0

    :goto_0
    iget v1, p0, La/e/b/d;->l:I

    if-ge v0, v1, :cond_0

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v1, v1, v0

    iget-object v2, v1, La/e/b/b;->a:La/e/b/g;

    iget v1, v1, La/e/b/b;->b:F

    iput v1, v2, La/e/b/g;->f:F

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public k(ILjava/lang/String;)La/e/b/g;
    .locals 2

    iget v0, p0, La/e/b/d;->k:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, La/e/b/d;->f:I

    if-lt v0, v1, :cond_0

    invoke-virtual {p0}, La/e/b/d;->p()V

    :cond_0
    sget-object v0, La/e/b/g$a;->e:La/e/b/g$a;

    invoke-virtual {p0, v0, p2}, La/e/b/d;->a(La/e/b/g$a;Ljava/lang/String;)La/e/b/g;

    move-result-object p2

    iget v0, p0, La/e/b/d;->b:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, La/e/b/d;->b:I

    iget v1, p0, La/e/b/d;->k:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, La/e/b/d;->k:I

    iput v0, p2, La/e/b/g;->c:I

    iput p1, p2, La/e/b/g;->e:I

    iget-object p1, p0, La/e/b/d;->n:La/e/b/c;

    iget-object p1, p1, La/e/b/c;->d:[La/e/b/g;

    aput-object p2, p1, v0

    iget-object p1, p0, La/e/b/d;->d:La/e/b/d$a;

    invoke-interface {p1, p2}, La/e/b/d$a;->a(La/e/b/g;)V

    return-object p2
.end method

.method public l(Ljava/lang/Object;)La/e/b/g;
    .locals 3

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    iget v1, p0, La/e/b/d;->k:I

    add-int/lit8 v1, v1, 0x1

    iget v2, p0, La/e/b/d;->f:I

    if-lt v1, v2, :cond_1

    invoke-virtual {p0}, La/e/b/d;->p()V

    :cond_1
    instance-of v1, p1, La/e/b/h/c;

    if-eqz v1, :cond_5

    check-cast p1, La/e/b/h/c;

    .line 1
    iget-object v0, p1, La/e/b/h/c;->i:La/e/b/g;

    if-nez v0, :cond_2

    .line 2
    invoke-virtual {p1}, La/e/b/h/c;->i()V

    .line 3
    iget-object p1, p1, La/e/b/h/c;->i:La/e/b/g;

    move-object v0, p1

    .line 4
    :cond_2
    iget p1, v0, La/e/b/g;->c:I

    const/4 v1, -0x1

    if-eq p1, v1, :cond_3

    iget v2, p0, La/e/b/d;->b:I

    if-gt p1, v2, :cond_3

    iget-object v2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v2, v2, La/e/b/c;->d:[La/e/b/g;

    aget-object p1, v2, p1

    if-nez p1, :cond_5

    :cond_3
    iget p1, v0, La/e/b/g;->c:I

    if-eq p1, v1, :cond_4

    invoke-virtual {v0}, La/e/b/g;->c()V

    :cond_4
    iget p1, p0, La/e/b/d;->b:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, La/e/b/d;->b:I

    iget v1, p0, La/e/b/d;->k:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, La/e/b/d;->k:I

    iput p1, v0, La/e/b/g;->c:I

    sget-object v1, La/e/b/g$a;->b:La/e/b/g$a;

    iput-object v1, v0, La/e/b/g;->j:La/e/b/g$a;

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v1, v1, La/e/b/c;->d:[La/e/b/g;

    aput-object v0, v1, p1

    :cond_5
    return-object v0
.end method

.method public m()La/e/b/b;
    .locals 5

    iget-object v0, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v0, v0, La/e/b/c;->b:La/e/b/e;

    invoke-virtual {v0}, La/e/b/e;->a()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/b;

    if-nez v0, :cond_0

    new-instance v0, La/e/b/b;

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    invoke-direct {v0, v1}, La/e/b/b;-><init>(La/e/b/c;)V

    sget-wide v1, La/e/b/d;->t:J

    const-wide/16 v3, 0x1

    add-long/2addr v1, v3

    sput-wide v1, La/e/b/d;->t:J

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    .line 1
    iput-object v1, v0, La/e/b/b;->a:La/e/b/g;

    iget-object v1, v0, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v1}, La/e/b/b$a;->clear()V

    const/4 v1, 0x0

    iput v1, v0, La/e/b/b;->b:F

    const/4 v1, 0x0

    iput-boolean v1, v0, La/e/b/b;->f:Z

    .line 2
    :goto_0
    sget v1, La/e/b/g;->q:I

    add-int/lit8 v1, v1, 0x1

    sput v1, La/e/b/g;->q:I

    return-object v0
.end method

.method public n()La/e/b/g;
    .locals 3

    iget v0, p0, La/e/b/d;->k:I

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, La/e/b/d;->f:I

    if-lt v0, v1, :cond_0

    invoke-virtual {p0}, La/e/b/d;->p()V

    :cond_0
    sget-object v0, La/e/b/g$a;->d:La/e/b/g$a;

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, La/e/b/d;->a(La/e/b/g$a;Ljava/lang/String;)La/e/b/g;

    move-result-object v0

    iget v1, p0, La/e/b/d;->b:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, La/e/b/d;->b:I

    iget v2, p0, La/e/b/d;->k:I

    add-int/lit8 v2, v2, 0x1

    iput v2, p0, La/e/b/d;->k:I

    iput v1, v0, La/e/b/g;->c:I

    iget-object v2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v2, v2, La/e/b/c;->d:[La/e/b/g;

    aput-object v0, v2, v1

    return-object v0
.end method

.method public o(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, La/e/b/h/c;

    .line 1
    iget-object p1, p1, La/e/b/h/c;->i:La/e/b/g;

    if-eqz p1, :cond_0

    .line 2
    iget p1, p1, La/e/b/g;->f:F

    const/high16 v0, 0x3f000000    # 0.5f

    add-float/2addr p1, v0

    float-to-int p1, p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final p()V
    .locals 3

    iget v0, p0, La/e/b/d;->e:I

    mul-int/lit8 v0, v0, 0x2

    iput v0, p0, La/e/b/d;->e:I

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/e/b/b;

    iput-object v0, p0, La/e/b/d;->g:[La/e/b/b;

    iget-object v0, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v1, v0, La/e/b/c;->d:[La/e/b/g;

    iget v2, p0, La/e/b/d;->e:I

    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [La/e/b/g;

    iput-object v1, v0, La/e/b/c;->d:[La/e/b/g;

    iget v0, p0, La/e/b/d;->e:I

    new-array v1, v0, [Z

    iput-object v1, p0, La/e/b/d;->j:[Z

    iput v0, p0, La/e/b/d;->f:I

    iput v0, p0, La/e/b/d;->m:I

    return-void
.end method

.method public q()V
    .locals 3

    iget-object v0, p0, La/e/b/d;->d:La/e/b/d$a;

    invoke-interface {v0}, La/e/b/d$a;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, La/e/b/d;->j()V

    return-void

    :cond_0
    iget-boolean v0, p0, La/e/b/d;->h:Z

    if-nez v0, :cond_2

    iget-boolean v0, p0, La/e/b/d;->i:Z

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, La/e/b/d;->d:La/e/b/d$a;

    invoke-virtual {p0, v0}, La/e/b/d;->r(La/e/b/d$a;)V

    goto :goto_4

    :cond_2
    :goto_1
    const/4 v0, 0x0

    move v1, v0

    :goto_2
    iget v2, p0, La/e/b/d;->l:I

    if-ge v1, v2, :cond_4

    iget-object v2, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v2, v2, v1

    iget-boolean v2, v2, La/e/b/b;->f:Z

    if-nez v2, :cond_3

    goto :goto_3

    :cond_3
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_4
    const/4 v0, 0x1

    :goto_3
    if-nez v0, :cond_5

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, La/e/b/d;->j()V

    :goto_4
    return-void
.end method

.method public r(La/e/b/d$a;)V
    .locals 18

    move-object/from16 v0, p0

    .line 1
    sget-object v1, La/e/b/g$a;->b:La/e/b/g$a;

    const/4 v3, 0x0

    :goto_0
    iget v4, v0, La/e/b/d;->l:I

    const/4 v5, 0x0

    const/4 v6, 0x1

    if-ge v3, v4, :cond_2

    iget-object v4, v0, La/e/b/d;->g:[La/e/b/b;

    aget-object v7, v4, v3

    iget-object v7, v7, La/e/b/b;->a:La/e/b/g;

    iget-object v7, v7, La/e/b/g;->j:La/e/b/g$a;

    if-ne v7, v1, :cond_0

    goto :goto_1

    :cond_0
    aget-object v4, v4, v3

    iget v4, v4, La/e/b/b;->b:F

    cmpg-float v4, v4, v5

    if-gez v4, :cond_1

    move v3, v6

    goto :goto_2

    :cond_1
    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    const/4 v3, 0x0

    :goto_2
    if-eqz v3, :cond_e

    const/4 v3, 0x0

    const/4 v4, 0x0

    :goto_3
    if-nez v3, :cond_e

    add-int/2addr v4, v6

    const v7, 0x7f7fffff    # Float.MAX_VALUE

    const/4 v9, 0x0

    const/4 v10, -0x1

    const/4 v11, -0x1

    const/4 v12, 0x0

    :goto_4
    iget v13, v0, La/e/b/d;->l:I

    if-ge v9, v13, :cond_b

    iget-object v13, v0, La/e/b/d;->g:[La/e/b/b;

    aget-object v13, v13, v9

    iget-object v14, v13, La/e/b/b;->a:La/e/b/g;

    iget-object v14, v14, La/e/b/g;->j:La/e/b/g$a;

    if-ne v14, v1, :cond_3

    goto :goto_8

    :cond_3
    iget-boolean v14, v13, La/e/b/b;->f:Z

    if-eqz v14, :cond_4

    goto :goto_8

    :cond_4
    iget v14, v13, La/e/b/b;->b:F

    cmpg-float v14, v14, v5

    if-gez v14, :cond_a

    iget-object v14, v13, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v14}, La/e/b/b$a;->k()I

    move-result v14

    const/4 v15, 0x0

    :goto_5
    if-ge v15, v14, :cond_a

    iget-object v2, v13, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v2, v15}, La/e/b/b$a;->d(I)La/e/b/g;

    move-result-object v2

    iget-object v6, v13, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v6, v2}, La/e/b/b$a;->e(La/e/b/g;)F

    move-result v6

    cmpg-float v16, v6, v5

    if-gtz v16, :cond_5

    goto :goto_7

    :cond_5
    const/4 v5, 0x0

    :goto_6
    const/16 v8, 0x9

    if-ge v5, v8, :cond_9

    iget-object v8, v2, La/e/b/g;->h:[F

    aget v8, v8, v5

    div-float/2addr v8, v6

    cmpg-float v17, v8, v7

    if-gez v17, :cond_6

    if-eq v5, v12, :cond_7

    :cond_6
    if-le v5, v12, :cond_8

    :cond_7
    iget v11, v2, La/e/b/g;->c:I

    move v12, v5

    move v7, v8

    move v10, v9

    :cond_8
    add-int/lit8 v5, v5, 0x1

    goto :goto_6

    :cond_9
    :goto_7
    add-int/lit8 v15, v15, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x1

    goto :goto_5

    :cond_a
    :goto_8
    add-int/lit8 v9, v9, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x1

    goto :goto_4

    :cond_b
    const/4 v2, -0x1

    if-eq v10, v2, :cond_c

    iget-object v5, v0, La/e/b/d;->g:[La/e/b/b;

    aget-object v5, v5, v10

    iget-object v6, v5, La/e/b/b;->a:La/e/b/g;

    iput v2, v6, La/e/b/g;->d:I

    iget-object v2, v0, La/e/b/d;->n:La/e/b/c;

    iget-object v2, v2, La/e/b/c;->d:[La/e/b/g;

    aget-object v2, v2, v11

    invoke-virtual {v5, v2}, La/e/b/b;->j(La/e/b/g;)V

    iget-object v2, v5, La/e/b/b;->a:La/e/b/g;

    iput v10, v2, La/e/b/g;->d:I

    invoke-virtual {v2, v0, v5}, La/e/b/g;->e(La/e/b/d;La/e/b/b;)V

    goto :goto_9

    :cond_c
    const/4 v3, 0x1

    :goto_9
    iget v2, v0, La/e/b/d;->k:I

    div-int/lit8 v2, v2, 0x2

    if-le v4, v2, :cond_d

    const/4 v3, 0x1

    :cond_d
    const/4 v5, 0x0

    const/4 v6, 0x1

    goto/16 :goto_3

    .line 2
    :cond_e
    invoke-virtual/range {p0 .. p1}, La/e/b/d;->s(La/e/b/d$a;)I

    invoke-virtual/range {p0 .. p0}, La/e/b/d;->j()V

    return-void
.end method

.method public final s(La/e/b/d$a;)I
    .locals 12

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    iget v2, p0, La/e/b/d;->k:I

    if-ge v1, v2, :cond_0

    iget-object v2, p0, La/e/b/d;->j:[Z

    aput-boolean v0, v2, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x1

    move v2, v0

    move v3, v2

    :cond_1
    :goto_1
    if-nez v2, :cond_b

    add-int/lit8 v3, v3, 0x1

    iget v4, p0, La/e/b/d;->k:I

    mul-int/lit8 v4, v4, 0x2

    if-lt v3, v4, :cond_2

    return v3

    :cond_2
    move-object v4, p1

    check-cast v4, La/e/b/b;

    .line 1
    iget-object v4, v4, La/e/b/b;->a:La/e/b/g;

    if-eqz v4, :cond_3

    .line 2
    iget-object v5, p0, La/e/b/d;->j:[Z

    iget v4, v4, La/e/b/g;->c:I

    aput-boolean v1, v5, v4

    :cond_3
    iget-object v4, p0, La/e/b/d;->j:[Z

    invoke-interface {p1, p0, v4}, La/e/b/d$a;->b(La/e/b/d;[Z)La/e/b/g;

    move-result-object v4

    if-eqz v4, :cond_5

    iget-object v5, p0, La/e/b/d;->j:[Z

    iget v6, v4, La/e/b/g;->c:I

    aget-boolean v7, v5, v6

    if-eqz v7, :cond_4

    return v3

    :cond_4
    aput-boolean v1, v5, v6

    :cond_5
    if-eqz v4, :cond_a

    const v5, 0x7f7fffff    # Float.MAX_VALUE

    const/4 v6, -0x1

    move v7, v0

    move v8, v6

    :goto_2
    iget v9, p0, La/e/b/d;->l:I

    if-ge v7, v9, :cond_9

    iget-object v9, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v9, v9, v7

    iget-object v10, v9, La/e/b/b;->a:La/e/b/g;

    iget-object v10, v10, La/e/b/g;->j:La/e/b/g$a;

    sget-object v11, La/e/b/g$a;->b:La/e/b/g$a;

    if-ne v10, v11, :cond_6

    goto :goto_3

    :cond_6
    iget-boolean v10, v9, La/e/b/b;->f:Z

    if-eqz v10, :cond_7

    goto :goto_3

    .line 3
    :cond_7
    iget-object v10, v9, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v10, v4}, La/e/b/b$a;->g(La/e/b/g;)Z

    move-result v10

    if-eqz v10, :cond_8

    .line 4
    iget-object v10, v9, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v10, v4}, La/e/b/b$a;->e(La/e/b/g;)F

    move-result v10

    const/4 v11, 0x0

    cmpg-float v11, v10, v11

    if-gez v11, :cond_8

    iget v9, v9, La/e/b/b;->b:F

    neg-float v9, v9

    div-float/2addr v9, v10

    cmpg-float v10, v9, v5

    if-gez v10, :cond_8

    move v8, v7

    move v5, v9

    :cond_8
    :goto_3
    add-int/lit8 v7, v7, 0x1

    goto :goto_2

    :cond_9
    if-le v8, v6, :cond_1

    iget-object v5, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v5, v5, v8

    iget-object v7, v5, La/e/b/b;->a:La/e/b/g;

    iput v6, v7, La/e/b/g;->d:I

    invoke-virtual {v5, v4}, La/e/b/b;->j(La/e/b/g;)V

    iget-object v4, v5, La/e/b/b;->a:La/e/b/g;

    iput v8, v4, La/e/b/g;->d:I

    invoke-virtual {v4, p0, v5}, La/e/b/g;->e(La/e/b/d;La/e/b/b;)V

    goto :goto_1

    :cond_a
    move v2, v1

    goto :goto_1

    :cond_b
    return v3
.end method

.method public final t()V
    .locals 3

    const/4 v0, 0x0

    :goto_0
    iget v1, p0, La/e/b/d;->l:I

    if-ge v0, v1, :cond_1

    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v1, v1, v0

    if-eqz v1, :cond_0

    iget-object v2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v2, v2, La/e/b/c;->b:La/e/b/e;

    invoke-virtual {v2, v1}, La/e/b/e;->b(Ljava/lang/Object;)Z

    :cond_0
    iget-object v1, p0, La/e/b/d;->g:[La/e/b/b;

    const/4 v2, 0x0

    aput-object v2, v1, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public u()V
    .locals 10

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    iget-object v2, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v3, v2, La/e/b/c;->d:[La/e/b/g;

    array-length v4, v3

    if-ge v1, v4, :cond_1

    aget-object v2, v3, v1

    if-eqz v2, :cond_0

    invoke-virtual {v2}, La/e/b/g;->c()V

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    iget-object v1, v2, La/e/b/c;->c:La/e/b/e;

    iget-object v2, p0, La/e/b/d;->o:[La/e/b/g;

    iget v3, p0, La/e/b/d;->p:I

    const/4 v4, 0x0

    if-eqz v1, :cond_8

    .line 1
    array-length v5, v2

    if-le v3, v5, :cond_2

    array-length v3, v2

    :cond_2
    move v5, v0

    :goto_1
    if-ge v5, v3, :cond_4

    aget-object v6, v2, v5

    iget v7, v1, La/e/b/e;->b:I

    iget-object v8, v1, La/e/b/e;->a:[Ljava/lang/Object;

    array-length v9, v8

    if-ge v7, v9, :cond_3

    aput-object v6, v8, v7

    add-int/lit8 v7, v7, 0x1

    iput v7, v1, La/e/b/e;->b:I

    :cond_3
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    .line 2
    :cond_4
    iput v0, p0, La/e/b/d;->p:I

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    iget-object v1, v1, La/e/b/c;->d:[La/e/b/g;

    invoke-static {v1, v4}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v1, p0, La/e/b/d;->c:Ljava/util/HashMap;

    if-eqz v1, :cond_5

    invoke-virtual {v1}, Ljava/util/HashMap;->clear()V

    :cond_5
    iput v0, p0, La/e/b/d;->b:I

    iget-object v1, p0, La/e/b/d;->d:La/e/b/d$a;

    invoke-interface {v1}, La/e/b/d$a;->clear()V

    const/4 v1, 0x1

    iput v1, p0, La/e/b/d;->k:I

    move v1, v0

    :goto_2
    iget v2, p0, La/e/b/d;->l:I

    if-ge v1, v2, :cond_7

    iget-object v2, p0, La/e/b/d;->g:[La/e/b/b;

    aget-object v3, v2, v1

    if-eqz v3, :cond_6

    aget-object v2, v2, v1

    iput-boolean v0, v2, La/e/b/b;->c:Z

    :cond_6
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_7
    invoke-virtual {p0}, La/e/b/d;->t()V

    iput v0, p0, La/e/b/d;->l:I

    new-instance v0, La/e/b/b;

    iget-object v1, p0, La/e/b/d;->n:La/e/b/c;

    invoke-direct {v0, v1}, La/e/b/b;-><init>(La/e/b/c;)V

    iput-object v0, p0, La/e/b/d;->q:La/e/b/d$a;

    return-void

    .line 3
    :cond_8
    throw v4
.end method
