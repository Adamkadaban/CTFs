.class public La/e/b/f;
.super La/e/b/b;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/f$b;
    }
.end annotation


# instance fields
.field public g:I

.field public h:[La/e/b/g;

.field public i:[La/e/b/g;

.field public j:I

.field public k:La/e/b/f$b;


# direct methods
.method public constructor <init>(La/e/b/c;)V
    .locals 1

    invoke-direct {p0, p1}, La/e/b/b;-><init>(La/e/b/c;)V

    const/16 p1, 0x80

    iput p1, p0, La/e/b/f;->g:I

    new-array v0, p1, [La/e/b/g;

    iput-object v0, p0, La/e/b/f;->h:[La/e/b/g;

    new-array p1, p1, [La/e/b/g;

    iput-object p1, p0, La/e/b/f;->i:[La/e/b/g;

    const/4 p1, 0x0

    iput p1, p0, La/e/b/f;->j:I

    new-instance p1, La/e/b/f$b;

    invoke-direct {p1, p0, p0}, La/e/b/f$b;-><init>(La/e/b/f;La/e/b/f;)V

    iput-object p1, p0, La/e/b/f;->k:La/e/b/f$b;

    return-void
.end method


# virtual methods
.method public a(La/e/b/g;)V
    .locals 3

    iget-object v0, p0, La/e/b/f;->k:La/e/b/f$b;

    .line 1
    iput-object p1, v0, La/e/b/f$b;->b:La/e/b/g;

    .line 2
    iget-object v0, p1, La/e/b/g;->i:[F

    const/4 v1, 0x0

    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([FF)V

    .line 3
    iget-object v0, p1, La/e/b/g;->i:[F

    iget v1, p1, La/e/b/g;->e:I

    const/high16 v2, 0x3f800000    # 1.0f

    aput v2, v0, v1

    invoke-virtual {p0, p1}, La/e/b/f;->m(La/e/b/g;)V

    return-void
.end method

.method public b(La/e/b/d;[Z)La/e/b/g;
    .locals 10

    const/4 p1, 0x0

    const/4 v0, -0x1

    move v1, p1

    move v2, v0

    :goto_0
    iget v3, p0, La/e/b/f;->j:I

    const/4 v4, 0x0

    if-ge v1, v3, :cond_a

    iget-object v3, p0, La/e/b/f;->h:[La/e/b/g;

    aget-object v5, v3, v1

    iget v6, v5, La/e/b/g;->c:I

    aget-boolean v6, p2, v6

    if-eqz v6, :cond_0

    goto :goto_7

    :cond_0
    iget-object v6, p0, La/e/b/f;->k:La/e/b/f$b;

    .line 1
    iput-object v5, v6, La/e/b/f$b;->b:La/e/b/g;

    const/16 v5, 0x8

    const/4 v7, 0x1

    if-ne v2, v0, :cond_5

    if-eqz v6, :cond_4

    :goto_1
    if-ltz v5, :cond_3

    .line 2
    iget-object v3, v6, La/e/b/f$b;->b:La/e/b/g;

    iget-object v3, v3, La/e/b/g;->i:[F

    aget v3, v3, v5

    const/4 v4, 0x0

    cmpl-float v8, v3, v4

    if-lez v8, :cond_1

    goto :goto_2

    :cond_1
    cmpg-float v3, v3, v4

    if-gez v3, :cond_2

    goto :goto_3

    :cond_2
    add-int/lit8 v5, v5, -0x1

    goto :goto_1

    :cond_3
    :goto_2
    move v7, p1

    :goto_3
    if-eqz v7, :cond_8

    goto :goto_6

    :cond_4
    throw v4

    .line 3
    :cond_5
    aget-object v3, v3, v2

    if-eqz v6, :cond_9

    :goto_4
    if-ltz v5, :cond_7

    .line 4
    iget-object v4, v3, La/e/b/g;->i:[F

    aget v4, v4, v5

    iget-object v8, v6, La/e/b/f$b;->b:La/e/b/g;

    iget-object v8, v8, La/e/b/g;->i:[F

    aget v8, v8, v5

    cmpl-float v9, v8, v4

    if-nez v9, :cond_6

    add-int/lit8 v5, v5, -0x1

    goto :goto_4

    :cond_6
    cmpg-float v3, v8, v4

    if-gez v3, :cond_7

    goto :goto_5

    :cond_7
    move v7, p1

    :goto_5
    if-eqz v7, :cond_8

    :goto_6
    move v2, v1

    :cond_8
    :goto_7
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_9
    throw v4

    :cond_a
    if-ne v2, v0, :cond_b

    return-object v4

    .line 5
    :cond_b
    iget-object p1, p0, La/e/b/f;->h:[La/e/b/g;

    aget-object p1, p1, v2

    return-object p1
.end method

.method public clear()V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La/e/b/f;->j:I

    const/4 v0, 0x0

    iput v0, p0, La/e/b/b;->b:F

    return-void
.end method

.method public isEmpty()Z
    .locals 1

    iget v0, p0, La/e/b/f;->j:I

    if-nez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public l(La/e/b/d;La/e/b/b;Z)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    iget-object v2, v1, La/e/b/b;->a:La/e/b/g;

    if-nez v2, :cond_0

    return-void

    :cond_0
    iget-object v3, v1, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v3}, La/e/b/b$a;->k()I

    move-result v4

    const/4 v6, 0x0

    :goto_0
    if-ge v6, v4, :cond_9

    invoke-interface {v3, v6}, La/e/b/b$a;->d(I)La/e/b/g;

    move-result-object v7

    invoke-interface {v3, v6}, La/e/b/b$a;->a(I)F

    move-result v8

    iget-object v9, v0, La/e/b/f;->k:La/e/b/f$b;

    .line 1
    iput-object v7, v9, La/e/b/f$b;->b:La/e/b/g;

    .line 2
    iget-boolean v10, v7, La/e/b/g;->a:Z

    const v11, 0x38d1b717    # 1.0E-4f

    const/16 v12, 0x9

    const/4 v13, 0x0

    const/4 v14, 0x1

    if-eqz v10, :cond_4

    const/4 v10, 0x0

    :goto_1
    if-ge v10, v12, :cond_2

    iget-object v15, v9, La/e/b/f$b;->b:La/e/b/g;

    iget-object v15, v15, La/e/b/g;->i:[F

    aget v16, v15, v10

    iget-object v5, v2, La/e/b/g;->i:[F

    aget v5, v5, v10

    mul-float/2addr v5, v8

    add-float v5, v5, v16

    aput v5, v15, v10

    aget v5, v15, v10

    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, v11

    if-gez v5, :cond_1

    iget-object v5, v9, La/e/b/f$b;->b:La/e/b/g;

    iget-object v5, v5, La/e/b/g;->i:[F

    aput v13, v5, v10

    goto :goto_2

    :cond_1
    const/4 v14, 0x0

    :goto_2
    add-int/lit8 v10, v10, 0x1

    goto :goto_1

    :cond_2
    if-eqz v14, :cond_3

    iget-object v5, v9, La/e/b/f$b;->c:La/e/b/f;

    iget-object v9, v9, La/e/b/f$b;->b:La/e/b/g;

    .line 3
    invoke-virtual {v5, v9}, La/e/b/f;->n(La/e/b/g;)V

    :cond_3
    const/4 v14, 0x0

    goto :goto_5

    :cond_4
    const/4 v5, 0x0

    :goto_3
    if-ge v5, v12, :cond_7

    .line 4
    iget-object v10, v2, La/e/b/g;->i:[F

    aget v10, v10, v5

    cmpl-float v15, v10, v13

    if-eqz v15, :cond_6

    mul-float/2addr v10, v8

    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v15

    cmpg-float v15, v15, v11

    if-gez v15, :cond_5

    move v10, v13

    :cond_5
    iget-object v15, v9, La/e/b/f$b;->b:La/e/b/g;

    iget-object v15, v15, La/e/b/g;->i:[F

    aput v10, v15, v5

    goto :goto_4

    :cond_6
    iget-object v10, v9, La/e/b/f$b;->b:La/e/b/g;

    iget-object v10, v10, La/e/b/g;->i:[F

    aput v13, v10, v5

    :goto_4
    add-int/lit8 v5, v5, 0x1

    goto :goto_3

    :cond_7
    :goto_5
    if-eqz v14, :cond_8

    .line 5
    invoke-virtual {v0, v7}, La/e/b/f;->m(La/e/b/g;)V

    :cond_8
    iget v5, v0, La/e/b/b;->b:F

    iget v7, v1, La/e/b/b;->b:F

    mul-float/2addr v7, v8

    add-float/2addr v7, v5

    iput v7, v0, La/e/b/b;->b:F

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_9
    invoke-virtual {v0, v2}, La/e/b/f;->n(La/e/b/g;)V

    return-void
.end method

.method public final m(La/e/b/g;)V
    .locals 5

    iget v0, p0, La/e/b/f;->j:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iget-object v2, p0, La/e/b/f;->h:[La/e/b/g;

    array-length v3, v2

    if-le v0, v3, :cond_0

    array-length v0, v2

    mul-int/lit8 v0, v0, 0x2

    invoke-static {v2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/e/b/g;

    iput-object v0, p0, La/e/b/f;->h:[La/e/b/g;

    array-length v2, v0

    mul-int/lit8 v2, v2, 0x2

    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/e/b/g;

    iput-object v0, p0, La/e/b/f;->i:[La/e/b/g;

    :cond_0
    iget-object v0, p0, La/e/b/f;->h:[La/e/b/g;

    iget v2, p0, La/e/b/f;->j:I

    aput-object p1, v0, v2

    add-int/2addr v2, v1

    iput v2, p0, La/e/b/f;->j:I

    if-le v2, v1, :cond_2

    sub-int/2addr v2, v1

    aget-object v0, v0, v2

    iget v0, v0, La/e/b/g;->c:I

    iget v2, p1, La/e/b/g;->c:I

    if-le v0, v2, :cond_2

    const/4 v0, 0x0

    move v2, v0

    :goto_0
    iget v3, p0, La/e/b/f;->j:I

    if-ge v2, v3, :cond_1

    iget-object v3, p0, La/e/b/f;->i:[La/e/b/g;

    iget-object v4, p0, La/e/b/f;->h:[La/e/b/g;

    aget-object v4, v4, v2

    aput-object v4, v3, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    iget-object v2, p0, La/e/b/f;->i:[La/e/b/g;

    new-instance v4, La/e/b/f$a;

    invoke-direct {v4, p0}, La/e/b/f$a;-><init>(La/e/b/f;)V

    invoke-static {v2, v0, v3, v4}, Ljava/util/Arrays;->sort([Ljava/lang/Object;IILjava/util/Comparator;)V

    :goto_1
    iget v2, p0, La/e/b/f;->j:I

    if-ge v0, v2, :cond_2

    iget-object v2, p0, La/e/b/f;->h:[La/e/b/g;

    iget-object v3, p0, La/e/b/f;->i:[La/e/b/g;

    aget-object v3, v3, v0

    aput-object v3, v2, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_2
    iput-boolean v1, p1, La/e/b/g;->a:Z

    invoke-virtual {p1, p0}, La/e/b/g;->a(La/e/b/b;)V

    return-void
.end method

.method public final n(La/e/b/g;)V
    .locals 5

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    iget v2, p0, La/e/b/f;->j:I

    if-ge v1, v2, :cond_2

    iget-object v2, p0, La/e/b/f;->h:[La/e/b/g;

    aget-object v2, v2, v1

    if-ne v2, p1, :cond_1

    :goto_1
    iget v2, p0, La/e/b/f;->j:I

    add-int/lit8 v3, v2, -0x1

    if-ge v1, v3, :cond_0

    iget-object v2, p0, La/e/b/f;->h:[La/e/b/g;

    add-int/lit8 v3, v1, 0x1

    aget-object v4, v2, v3

    aput-object v4, v2, v1

    move v1, v3

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, -0x1

    iput v2, p0, La/e/b/f;->j:I

    iput-boolean v0, p1, La/e/b/g;->a:Z

    return-void

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, ""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " goal -> ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/e/b/b;->b:F

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v1, ") : "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    :goto_0
    iget v2, p0, La/e/b/f;->j:I

    if-ge v1, v2, :cond_0

    iget-object v2, p0, La/e/b/f;->h:[La/e/b/g;

    aget-object v2, v2, v1

    iget-object v3, p0, La/e/b/f;->k:La/e/b/f$b;

    .line 1
    iput-object v2, v3, La/e/b/f$b;->b:La/e/b/g;

    .line 2
    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v2, p0, La/e/b/f;->k:La/e/b/f$b;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method
