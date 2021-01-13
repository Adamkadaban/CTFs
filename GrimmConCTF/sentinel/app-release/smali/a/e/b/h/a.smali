.class public La/e/b/h/a;
.super La/e/b/h/h;
.source ""


# instance fields
.field public q0:I

.field public r0:Z

.field public s0:I

.field public t0:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, La/e/b/h/h;-><init>()V

    const/4 v0, 0x0

    iput v0, p0, La/e/b/h/a;->q0:I

    const/4 v1, 0x1

    iput-boolean v1, p0, La/e/b/h/a;->r0:Z

    iput v0, p0, La/e/b/h/a;->s0:I

    iput-boolean v0, p0, La/e/b/h/a;->t0:Z

    return-void
.end method


# virtual methods
.method public A()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/a;->t0:Z

    return v0
.end method

.method public Q()Z
    .locals 12

    sget-object v0, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    sget-object v1, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    sget-object v2, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    sget-object v3, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    const/4 v4, 0x0

    const/4 v5, 0x1

    move v6, v4

    move v7, v5

    :goto_0
    iget v8, p0, La/e/b/h/h;->p0:I

    const/4 v9, 0x3

    const/4 v10, 0x2

    if-ge v6, v8, :cond_5

    iget-object v8, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v8, v8, v6

    iget-boolean v11, p0, La/e/b/h/a;->r0:Z

    if-nez v11, :cond_0

    invoke-virtual {v8}, La/e/b/h/d;->e()Z

    move-result v11

    if-nez v11, :cond_0

    goto :goto_2

    :cond_0
    iget v11, p0, La/e/b/h/a;->q0:I

    if-eqz v11, :cond_1

    if-ne v11, v5, :cond_2

    :cond_1
    invoke-virtual {v8}, La/e/b/h/d;->z()Z

    move-result v11

    if-nez v11, :cond_2

    :goto_1
    move v7, v4

    goto :goto_2

    :cond_2
    iget v11, p0, La/e/b/h/a;->q0:I

    if-eq v11, v10, :cond_3

    if-ne v11, v9, :cond_4

    :cond_3
    invoke-virtual {v8}, La/e/b/h/d;->A()Z

    move-result v8

    if-nez v8, :cond_4

    goto :goto_1

    :cond_4
    :goto_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_5
    if-eqz v7, :cond_13

    if-lez v8, :cond_13

    move v6, v4

    move v7, v6

    :goto_3
    iget v8, p0, La/e/b/h/h;->p0:I

    if-ge v4, v8, :cond_10

    iget-object v8, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v8, v8, v4

    iget-boolean v11, p0, La/e/b/h/a;->r0:Z

    if-nez v11, :cond_6

    invoke-virtual {v8}, La/e/b/h/d;->e()Z

    move-result v11

    if-nez v11, :cond_6

    goto :goto_8

    :cond_6
    if-nez v7, :cond_b

    iget v7, p0, La/e/b/h/a;->q0:I

    if-nez v7, :cond_7

    invoke-virtual {v8, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v6

    :goto_4
    invoke-virtual {v6}, La/e/b/h/c;->c()I

    move-result v6

    goto :goto_5

    :cond_7
    if-ne v7, v5, :cond_8

    invoke-virtual {v8, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v6

    goto :goto_4

    :cond_8
    if-ne v7, v10, :cond_9

    invoke-virtual {v8, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v6

    goto :goto_4

    :cond_9
    if-ne v7, v9, :cond_a

    invoke-virtual {v8, v0}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v6

    goto :goto_4

    :cond_a
    :goto_5
    move v7, v5

    :cond_b
    iget v11, p0, La/e/b/h/a;->q0:I

    if-nez v11, :cond_c

    invoke-virtual {v8, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    :goto_6
    invoke-virtual {v8}, La/e/b/h/c;->c()I

    move-result v8

    invoke-static {v6, v8}, Ljava/lang/Math;->min(II)I

    move-result v6

    goto :goto_8

    :cond_c
    if-ne v11, v5, :cond_d

    invoke-virtual {v8, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    :goto_7
    invoke-virtual {v8}, La/e/b/h/c;->c()I

    move-result v8

    invoke-static {v6, v8}, Ljava/lang/Math;->max(II)I

    move-result v6

    goto :goto_8

    :cond_d
    if-ne v11, v10, :cond_e

    invoke-virtual {v8, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    goto :goto_6

    :cond_e
    if-ne v11, v9, :cond_f

    invoke-virtual {v8, v0}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    goto :goto_7

    :cond_f
    :goto_8
    add-int/lit8 v4, v4, 0x1

    goto :goto_3

    :cond_10
    iget v0, p0, La/e/b/h/a;->s0:I

    add-int/2addr v6, v0

    iget v0, p0, La/e/b/h/a;->q0:I

    if-eqz v0, :cond_12

    if-ne v0, v5, :cond_11

    goto :goto_9

    :cond_11
    invoke-virtual {p0, v6, v6}, La/e/b/h/d;->G(II)V

    goto :goto_a

    :cond_12
    :goto_9
    invoke-virtual {p0, v6, v6}, La/e/b/h/d;->F(II)V

    :goto_a
    iput-boolean v5, p0, La/e/b/h/a;->t0:Z

    return v5

    :cond_13
    return v4
.end method

.method public R()I
    .locals 3

    iget v0, p0, La/e/b/h/a;->q0:I

    if-eqz v0, :cond_1

    const/4 v1, 0x1

    if-eq v0, v1, :cond_1

    const/4 v2, 0x2

    if-eq v0, v2, :cond_0

    const/4 v2, 0x3

    if-eq v0, v2, :cond_0

    const/4 v0, -0x1

    return v0

    :cond_0
    return v1

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public d(La/e/b/d;Z)V
    .locals 13

    sget-object p2, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    iget-object v0, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    iget-object v1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    const/4 v2, 0x0

    aput-object v1, v0, v2

    iget-object v1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    const/4 v3, 0x2

    aput-object v1, v0, v3

    iget-object v1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    const/4 v4, 0x1

    aput-object v1, v0, v4

    iget-object v1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    const/4 v5, 0x3

    aput-object v1, v0, v5

    move v0, v2

    :goto_0
    iget-object v1, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    array-length v6, v1

    if-ge v0, v6, :cond_0

    aget-object v6, v1, v0

    aget-object v1, v1, v0

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v1

    iput-object v1, v6, La/e/b/h/c;->i:La/e/b/g;

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    iget v0, p0, La/e/b/h/a;->q0:I

    if-ltz v0, :cond_1f

    const/4 v6, 0x4

    if-ge v0, v6, :cond_1f

    aget-object v0, v1, v0

    iget-boolean v1, p0, La/e/b/h/a;->t0:Z

    if-nez v1, :cond_1

    invoke-virtual {p0}, La/e/b/h/a;->Q()Z

    :cond_1
    iget-boolean v1, p0, La/e/b/h/a;->t0:Z

    if-eqz v1, :cond_6

    iput-boolean v2, p0, La/e/b/h/a;->t0:Z

    iget p2, p0, La/e/b/h/a;->q0:I

    if-eqz p2, :cond_4

    if-ne p2, v4, :cond_2

    goto :goto_1

    :cond_2
    if-eq p2, v3, :cond_3

    if-ne p2, v5, :cond_5

    :cond_3
    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget v0, p0, La/e/b/h/d;->X:I

    invoke-virtual {p1, p2, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object p2, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget v0, p0, La/e/b/h/d;->X:I

    goto :goto_2

    :cond_4
    :goto_1
    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget v0, p0, La/e/b/h/d;->W:I

    invoke-virtual {p1, p2, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object p2, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget v0, p0, La/e/b/h/d;->W:I

    :goto_2
    invoke-virtual {p1, p2, v0}, La/e/b/d;->e(La/e/b/g;I)V

    :cond_5
    return-void

    :cond_6
    move v1, v2

    :goto_3
    iget v7, p0, La/e/b/h/h;->p0:I

    if-ge v1, v7, :cond_c

    iget-object v7, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v7, v7, v1

    iget-boolean v8, p0, La/e/b/h/a;->r0:Z

    if-nez v8, :cond_7

    invoke-virtual {v7}, La/e/b/h/d;->e()Z

    move-result v8

    if-nez v8, :cond_7

    goto :goto_5

    :cond_7
    iget v8, p0, La/e/b/h/a;->q0:I

    if-eqz v8, :cond_8

    if-ne v8, v4, :cond_9

    :cond_8
    invoke-virtual {v7}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v8

    if-ne v8, p2, :cond_9

    iget-object v8, v7, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v8, v8, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v8, :cond_9

    iget-object v8, v7, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v8, v8, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v8, :cond_9

    :goto_4
    move p2, v4

    goto :goto_6

    :cond_9
    iget v8, p0, La/e/b/h/a;->q0:I

    if-eq v8, v3, :cond_a

    if-ne v8, v5, :cond_b

    :cond_a
    invoke-virtual {v7}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v8

    if-ne v8, p2, :cond_b

    iget-object v8, v7, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v8, v8, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v8, :cond_b

    iget-object v7, v7, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v7, v7, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v7, :cond_b

    goto :goto_4

    :cond_b
    :goto_5
    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    :cond_c
    move p2, v2

    :goto_6
    iget-object v1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->e()Z

    move-result v1

    if-nez v1, :cond_e

    iget-object v1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->e()Z

    move-result v1

    if-eqz v1, :cond_d

    goto :goto_7

    :cond_d
    move v1, v2

    goto :goto_8

    :cond_e
    :goto_7
    move v1, v4

    :goto_8
    iget-object v7, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v7}, La/e/b/h/c;->e()Z

    move-result v7

    if-nez v7, :cond_10

    iget-object v7, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v7}, La/e/b/h/c;->e()Z

    move-result v7

    if-eqz v7, :cond_f

    goto :goto_9

    :cond_f
    move v7, v2

    goto :goto_a

    :cond_10
    :goto_9
    move v7, v4

    :goto_a
    if-nez p2, :cond_15

    iget p2, p0, La/e/b/h/a;->q0:I

    if-nez p2, :cond_11

    if-nez v1, :cond_14

    :cond_11
    iget p2, p0, La/e/b/h/a;->q0:I

    if-ne p2, v3, :cond_12

    if-nez v7, :cond_14

    :cond_12
    iget p2, p0, La/e/b/h/a;->q0:I

    if-ne p2, v4, :cond_13

    if-nez v1, :cond_14

    :cond_13
    iget p2, p0, La/e/b/h/a;->q0:I

    if-ne p2, v5, :cond_15

    if-eqz v7, :cond_15

    :cond_14
    move p2, v4

    goto :goto_b

    :cond_15
    move p2, v2

    :goto_b
    const/4 v1, 0x5

    if-nez p2, :cond_16

    move v1, v6

    :cond_16
    move p2, v2

    :goto_c
    iget v7, p0, La/e/b/h/h;->p0:I

    if-ge p2, v7, :cond_1b

    iget-object v7, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v7, v7, p2

    iget-boolean v8, p0, La/e/b/h/a;->r0:Z

    if-nez v8, :cond_17

    invoke-virtual {v7}, La/e/b/h/d;->e()Z

    move-result v8

    if-nez v8, :cond_17

    goto :goto_10

    :cond_17
    iget-object v8, v7, La/e/b/h/d;->N:[La/e/b/h/c;

    iget v9, p0, La/e/b/h/a;->q0:I

    aget-object v8, v8, v9

    invoke-virtual {p1, v8}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v8

    iget-object v7, v7, La/e/b/h/d;->N:[La/e/b/h/c;

    iget v9, p0, La/e/b/h/a;->q0:I

    aget-object v10, v7, v9

    iput-object v8, v10, La/e/b/h/c;->i:La/e/b/g;

    aget-object v10, v7, v9

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v10, :cond_18

    aget-object v10, v7, v9

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v10, v10, La/e/b/h/c;->d:La/e/b/h/d;

    if-ne v10, p0, :cond_18

    aget-object v7, v7, v9

    iget v7, v7, La/e/b/h/c;->g:I

    add-int/2addr v7, v2

    goto :goto_d

    :cond_18
    move v7, v2

    :goto_d
    iget v9, p0, La/e/b/h/a;->q0:I

    if-eqz v9, :cond_1a

    if-ne v9, v3, :cond_19

    goto :goto_e

    :cond_19
    iget-object v9, v0, La/e/b/h/c;->i:La/e/b/g;

    iget v10, p0, La/e/b/h/a;->s0:I

    add-int/2addr v10, v7

    .line 1
    invoke-virtual {p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v11

    invoke-virtual {p1}, La/e/b/d;->n()La/e/b/g;

    move-result-object v12

    iput v2, v12, La/e/b/g;->e:I

    invoke-virtual {v11, v9, v8, v12, v10}, La/e/b/b;->e(La/e/b/g;La/e/b/g;La/e/b/g;I)La/e/b/b;

    invoke-virtual {p1, v11}, La/e/b/d;->c(La/e/b/b;)V

    goto :goto_f

    .line 2
    :cond_1a
    :goto_e
    iget-object v9, v0, La/e/b/h/c;->i:La/e/b/g;

    iget v10, p0, La/e/b/h/a;->s0:I

    sub-int/2addr v10, v7

    .line 3
    invoke-virtual {p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v11

    invoke-virtual {p1}, La/e/b/d;->n()La/e/b/g;

    move-result-object v12

    iput v2, v12, La/e/b/g;->e:I

    invoke-virtual {v11, v9, v8, v12, v10}, La/e/b/b;->f(La/e/b/g;La/e/b/g;La/e/b/g;I)La/e/b/b;

    invoke-virtual {p1, v11}, La/e/b/d;->c(La/e/b/b;)V

    .line 4
    :goto_f
    iget-object v9, v0, La/e/b/h/c;->i:La/e/b/g;

    iget v10, p0, La/e/b/h/a;->s0:I

    add-int/2addr v10, v7

    invoke-virtual {p1, v9, v8, v10, v1}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    :goto_10
    add-int/lit8 p2, p2, 0x1

    goto :goto_c

    :cond_1b
    iget p2, p0, La/e/b/h/a;->q0:I

    const/16 v0, 0x8

    if-nez p2, :cond_1c

    iget-object p2, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v1, v2, v0}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v0, v2, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->F:La/e/b/h/c;

    :goto_11
    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v0, v2, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_12

    :cond_1c
    if-ne p2, v4, :cond_1d

    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v1, v2, v0}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v0, v2, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    goto :goto_11

    :cond_1d
    if-ne p2, v3, :cond_1e

    iget-object p2, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v1, v2, v0}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v0, v2, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->G:La/e/b/h/c;

    goto :goto_11

    :cond_1e
    if-ne p2, v5, :cond_1f

    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v1, v2, v0}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {p1, p2, v0, v2, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object p2, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p2, p2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    goto :goto_11

    :cond_1f
    :goto_12
    return-void
.end method

.method public e()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    const-string v0, "[Barrier] "

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    .line 1
    iget-object v1, p0, La/e/b/h/d;->f0:Ljava/lang/String;

    .line 2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " {"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    :goto_0
    iget v2, p0, La/e/b/h/h;->p0:I

    if-ge v1, v2, :cond_1

    iget-object v2, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v2, v2, v1

    if-lez v1, :cond_0

    const-string v3, ", "

    invoke-static {v0, v3}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :cond_0
    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    .line 3
    iget-object v2, v2, La/e/b/h/d;->f0:Ljava/lang/String;

    .line 4
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    const-string v1, "}"

    invoke-static {v0, v1}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public z()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/a;->t0:Z

    return v0
.end method
