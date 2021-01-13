.class public La/e/b/h/l/h;
.super Ljava/lang/Object;
.source ""


# static fields
.field public static a:La/e/b/h/l/b$a;


# direct methods
.method public static constructor <clinit>()V
    .locals 1

    new-instance v0, La/e/b/h/l/b$a;

    invoke-direct {v0}, La/e/b/h/l/b$a;-><init>()V

    sput-object v0, La/e/b/h/l/h;->a:La/e/b/h/l/b$a;

    return-void
.end method

.method public static a(La/e/b/h/d;)Z
    .locals 8

    sget-object v0, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    invoke-virtual {p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v3

    invoke-virtual {p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v4

    .line 1
    iget-object v5, p0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v5, :cond_0

    .line 2
    check-cast v5, La/e/b/h/e;

    goto :goto_0

    :cond_0
    const/4 v5, 0x0

    :goto_0
    if-eqz v5, :cond_1

    invoke-virtual {v5}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v6

    :cond_1
    if-eqz v5, :cond_2

    invoke-virtual {v5}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v5

    :cond_2
    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-eq v3, v2, :cond_5

    if-eq v3, v1, :cond_5

    if-ne v3, v0, :cond_3

    iget v3, p0, La/e/b/h/d;->n:I

    if-nez v3, :cond_3

    iget v3, p0, La/e/b/h/d;->U:F

    cmpl-float v3, v3, v5

    if-nez v3, :cond_3

    invoke-virtual {p0, v6}, La/e/b/h/d;->u(I)Z

    move-result v3

    if-nez v3, :cond_5

    :cond_3
    invoke-virtual {p0}, La/e/b/h/d;->z()Z

    move-result v3

    if-eqz v3, :cond_4

    goto :goto_1

    :cond_4
    move v3, v6

    goto :goto_2

    :cond_5
    :goto_1
    move v3, v7

    :goto_2
    if-eq v4, v2, :cond_8

    if-eq v4, v1, :cond_8

    if-ne v4, v0, :cond_6

    iget v0, p0, La/e/b/h/d;->o:I

    if-nez v0, :cond_6

    iget v0, p0, La/e/b/h/d;->U:F

    cmpl-float v0, v0, v5

    if-nez v0, :cond_6

    invoke-virtual {p0, v7}, La/e/b/h/d;->u(I)Z

    move-result v0

    if-nez v0, :cond_8

    :cond_6
    invoke-virtual {p0}, La/e/b/h/d;->A()Z

    move-result v0

    if-eqz v0, :cond_7

    goto :goto_3

    :cond_7
    move v0, v6

    goto :goto_4

    :cond_8
    :goto_3
    move v0, v7

    :goto_4
    iget p0, p0, La/e/b/h/d;->U:F

    cmpl-float p0, p0, v5

    if-lez p0, :cond_a

    if-nez v3, :cond_9

    if-eqz v0, :cond_a

    :cond_9
    return v7

    :cond_a
    if-eqz v3, :cond_b

    if-eqz v0, :cond_b

    move v6, v7

    :cond_b
    return v6
.end method

.method public static b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V
    .locals 13

    sget-object v0, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    instance-of v1, p0, La/e/b/h/e;

    const/4 v2, 0x0

    if-nez v1, :cond_0

    invoke-virtual {p0}, La/e/b/h/d;->y()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {p0}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, La/e/b/h/l/b$a;

    invoke-direct {v1}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {p0, p1, v1, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_0
    sget-object v1, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-virtual {p0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v1

    sget-object v3, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    invoke-virtual {p0, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v3

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v4

    invoke-virtual {v3}, La/e/b/h/c;->c()I

    move-result v5

    .line 1
    iget-object v6, v1, La/e/b/h/c;->a:Ljava/util/HashSet;

    const/4 v7, 0x0

    const/16 v8, 0x8

    const/4 v9, 0x1

    if-eqz v6, :cond_c

    .line 2
    iget-boolean v1, v1, La/e/b/h/c;->c:Z

    if-eqz v1, :cond_c

    .line 3
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_c

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/c;

    iget-object v10, v6, La/e/b/h/c;->d:La/e/b/h/d;

    invoke-static {v10}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v11

    invoke-virtual {v10}, La/e/b/h/d;->y()Z

    move-result v12

    if-eqz v12, :cond_2

    if-eqz v11, :cond_2

    new-instance v12, La/e/b/h/l/b$a;

    invoke-direct {v12}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {v10, p1, v12, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_2
    invoke-virtual {v10}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v12

    if-ne v12, v0, :cond_8

    if-eqz v11, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v10}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v11

    if-ne v11, v0, :cond_1

    iget v11, v10, La/e/b/h/d;->r:I

    if-ltz v11, :cond_1

    iget v11, v10, La/e/b/h/d;->q:I

    if-ltz v11, :cond_1

    .line 4
    iget v11, v10, La/e/b/h/d;->e0:I

    if-eq v11, v8, :cond_4

    .line 5
    iget v11, v10, La/e/b/h/d;->n:I

    if-nez v11, :cond_1

    .line 6
    iget v11, v10, La/e/b/h/d;->U:F

    cmpl-float v11, v11, v7

    if-nez v11, :cond_1

    .line 7
    :cond_4
    invoke-virtual {v10}, La/e/b/h/d;->w()Z

    move-result v11

    if-nez v11, :cond_1

    .line 8
    iget-boolean v11, v10, La/e/b/h/d;->C:Z

    if-nez v11, :cond_1

    .line 9
    iget-object v11, v10, La/e/b/h/d;->F:La/e/b/h/c;

    if-ne v6, v11, :cond_5

    iget-object v11, v10, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v11, v11, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v11, :cond_5

    .line 10
    iget-boolean v11, v11, La/e/b/h/c;->c:Z

    if-nez v11, :cond_6

    .line 11
    :cond_5
    iget-object v11, v10, La/e/b/h/d;->H:La/e/b/h/c;

    if-ne v6, v11, :cond_7

    iget-object v6, v10, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_7

    .line 12
    iget-boolean v6, v6, La/e/b/h/c;->c:Z

    if-eqz v6, :cond_7

    :cond_6
    move v6, v9

    goto :goto_1

    :cond_7
    move v6, v2

    :goto_1
    if-eqz v6, :cond_1

    .line 13
    invoke-virtual {v10}, La/e/b/h/d;->w()Z

    move-result v6

    if-nez v6, :cond_1

    invoke-static {p0, p1, v10, p2}, La/e/b/h/l/h;->d(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;Z)V

    goto :goto_0

    :cond_8
    :goto_2
    invoke-virtual {v10}, La/e/b/h/d;->y()Z

    move-result v11

    if-eqz v11, :cond_9

    goto/16 :goto_0

    :cond_9
    iget-object v11, v10, La/e/b/h/d;->F:La/e/b/h/c;

    if-ne v6, v11, :cond_a

    iget-object v12, v10, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v12, v12, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v12, :cond_a

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v6

    add-int/2addr v6, v4

    invoke-virtual {v10}, La/e/b/h/d;->r()I

    move-result v11

    add-int/2addr v11, v6

    invoke-virtual {v10, v6, v11}, La/e/b/h/d;->F(II)V

    goto :goto_3

    :cond_a
    iget-object v11, v10, La/e/b/h/d;->H:La/e/b/h/c;

    if-ne v6, v11, :cond_b

    iget-object v12, v10, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v12, v12, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v12, :cond_b

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v6

    sub-int v6, v4, v6

    invoke-virtual {v10}, La/e/b/h/d;->r()I

    move-result v11

    sub-int v11, v6, v11

    invoke-virtual {v10, v11, v6}, La/e/b/h/d;->F(II)V

    :goto_3
    invoke-static {v10, p1, p2}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    goto/16 :goto_0

    :cond_b
    iget-object v11, v10, La/e/b/h/d;->F:La/e/b/h/c;

    if-ne v6, v11, :cond_1

    iget-object v6, v10, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_1

    .line 14
    iget-boolean v6, v6, La/e/b/h/c;->c:Z

    if-eqz v6, :cond_1

    .line 15
    invoke-virtual {v10}, La/e/b/h/d;->w()Z

    move-result v6

    if-nez v6, :cond_1

    invoke-static {p1, v10, p2}, La/e/b/h/l/h;->c(La/e/b/h/l/b$b;La/e/b/h/d;Z)V

    goto/16 :goto_0

    :cond_c
    instance-of v1, p0, La/e/b/h/f;

    if-eqz v1, :cond_d

    return-void

    .line 16
    :cond_d
    iget-object v1, v3, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v1, :cond_19

    .line 17
    iget-boolean v3, v3, La/e/b/h/c;->c:Z

    if-eqz v3, :cond_19

    .line 18
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_e
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_19

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v4, v3, La/e/b/h/c;->d:La/e/b/h/d;

    invoke-static {v4}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v6

    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v10

    if-eqz v10, :cond_f

    if-eqz v6, :cond_f

    new-instance v10, La/e/b/h/l/b$a;

    invoke-direct {v10}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {v4, p1, v10, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_f
    iget-object v10, v4, La/e/b/h/d;->F:La/e/b/h/c;

    if-ne v3, v10, :cond_10

    iget-object v10, v4, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v10, :cond_10

    .line 19
    iget-boolean v10, v10, La/e/b/h/c;->c:Z

    if-nez v10, :cond_11

    .line 20
    :cond_10
    iget-object v10, v4, La/e/b/h/d;->H:La/e/b/h/c;

    if-ne v3, v10, :cond_12

    iget-object v10, v4, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v10, :cond_12

    .line 21
    iget-boolean v10, v10, La/e/b/h/c;->c:Z

    if-eqz v10, :cond_12

    :cond_11
    move v10, v9

    goto :goto_5

    :cond_12
    move v10, v2

    .line 22
    :goto_5
    invoke-virtual {v4}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v11

    if-ne v11, v0, :cond_15

    if-eqz v6, :cond_13

    goto :goto_6

    :cond_13
    invoke-virtual {v4}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object v3

    if-ne v3, v0, :cond_e

    iget v3, v4, La/e/b/h/d;->r:I

    if-ltz v3, :cond_e

    iget v3, v4, La/e/b/h/d;->q:I

    if-ltz v3, :cond_e

    .line 23
    iget v3, v4, La/e/b/h/d;->e0:I

    if-eq v3, v8, :cond_14

    .line 24
    iget v3, v4, La/e/b/h/d;->n:I

    if-nez v3, :cond_e

    .line 25
    iget v3, v4, La/e/b/h/d;->U:F

    cmpl-float v3, v3, v7

    if-nez v3, :cond_e

    .line 26
    :cond_14
    invoke-virtual {v4}, La/e/b/h/d;->w()Z

    move-result v3

    if-nez v3, :cond_e

    .line 27
    iget-boolean v3, v4, La/e/b/h/d;->C:Z

    if-nez v3, :cond_e

    if-eqz v10, :cond_e

    .line 28
    invoke-virtual {v4}, La/e/b/h/d;->w()Z

    move-result v3

    if-nez v3, :cond_e

    invoke-static {p0, p1, v4, p2}, La/e/b/h/l/h;->d(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;Z)V

    goto :goto_4

    :cond_15
    :goto_6
    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v6

    if-eqz v6, :cond_16

    goto/16 :goto_4

    :cond_16
    iget-object v6, v4, La/e/b/h/d;->F:La/e/b/h/c;

    if-ne v3, v6, :cond_17

    iget-object v11, v4, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v11, v11, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v11, :cond_17

    invoke-virtual {v6}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v5

    invoke-virtual {v4}, La/e/b/h/d;->r()I

    move-result v6

    add-int/2addr v6, v3

    invoke-virtual {v4, v3, v6}, La/e/b/h/d;->F(II)V

    goto :goto_7

    :cond_17
    iget-object v6, v4, La/e/b/h/d;->H:La/e/b/h/c;

    if-ne v3, v6, :cond_18

    iget-object v3, v4, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v3, :cond_18

    invoke-virtual {v6}, La/e/b/h/c;->d()I

    move-result v3

    sub-int v3, v5, v3

    invoke-virtual {v4}, La/e/b/h/d;->r()I

    move-result v6

    sub-int v6, v3, v6

    invoke-virtual {v4, v6, v3}, La/e/b/h/d;->F(II)V

    :goto_7
    invoke-static {v4, p1, p2}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    goto/16 :goto_4

    :cond_18
    if-eqz v10, :cond_e

    invoke-virtual {v4}, La/e/b/h/d;->w()Z

    move-result v3

    if-nez v3, :cond_e

    invoke-static {p1, v4, p2}, La/e/b/h/l/h;->c(La/e/b/h/l/b$b;La/e/b/h/d;Z)V

    goto/16 :goto_4

    :cond_19
    return-void
.end method

.method public static c(La/e/b/h/l/b$b;La/e/b/h/d;Z)V
    .locals 6

    .line 1
    iget v0, p1, La/e/b/h/d;->b0:F

    .line 2
    iget-object v1, p1, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v2, p1, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->c()I

    move-result v2

    iget-object v3, p1, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v1

    iget-object v4, p1, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    sub-int v4, v2, v4

    const/high16 v5, 0x3f000000    # 0.5f

    if-ne v1, v2, :cond_0

    move v0, v5

    goto :goto_0

    :cond_0
    move v1, v3

    move v2, v4

    :goto_0
    invoke-virtual {p1}, La/e/b/h/d;->r()I

    move-result v3

    sub-int v4, v2, v1

    sub-int/2addr v4, v3

    if-le v1, v2, :cond_1

    sub-int v4, v1, v2

    sub-int/2addr v4, v3

    :cond_1
    int-to-float v4, v4

    mul-float/2addr v0, v4

    add-float/2addr v0, v5

    float-to-int v0, v0

    add-int/2addr v0, v1

    add-int v4, v0, v3

    if-le v1, v2, :cond_2

    sub-int v4, v0, v3

    :cond_2
    invoke-virtual {p1, v0, v4}, La/e/b/h/d;->F(II)V

    invoke-static {p1, p0, p2}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    return-void
.end method

.method public static d(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;Z)V
    .locals 7

    .line 1
    iget v0, p2, La/e/b/h/d;->b0:F

    .line 2
    iget-object v1, p2, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v2, p2, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    add-int/2addr v2, v1

    iget-object v1, p2, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v3, p2, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    sub-int/2addr v1, v3

    if-lt v1, v2, :cond_4

    invoke-virtual {p2}, La/e/b/h/d;->r()I

    move-result v3

    .line 3
    iget v4, p2, La/e/b/h/d;->e0:I

    const/16 v5, 0x8

    const/high16 v6, 0x3f000000    # 0.5f

    if-eq v4, v5, :cond_3

    .line 4
    iget v4, p2, La/e/b/h/d;->n:I

    const/4 v5, 0x2

    if-ne v4, v5, :cond_1

    instance-of v3, p0, La/e/b/h/e;

    if-eqz v3, :cond_0

    goto :goto_0

    .line 5
    :cond_0
    iget-object p0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 6
    :goto_0
    invoke-virtual {p0}, La/e/b/h/d;->r()I

    move-result p0

    .line 7
    iget v3, p2, La/e/b/h/d;->b0:F

    mul-float/2addr v3, v6

    int-to-float p0, p0

    mul-float/2addr v3, p0

    float-to-int v3, v3

    goto :goto_1

    :cond_1
    if-nez v4, :cond_2

    sub-int v3, v1, v2

    .line 8
    :cond_2
    :goto_1
    iget p0, p2, La/e/b/h/d;->q:I

    invoke-static {p0, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    iget p0, p2, La/e/b/h/d;->r:I

    if-lez p0, :cond_3

    invoke-static {p0, v3}, Ljava/lang/Math;->min(II)I

    move-result v3

    :cond_3
    sub-int/2addr v1, v2

    sub-int/2addr v1, v3

    int-to-float p0, v1

    mul-float/2addr v0, p0

    add-float/2addr v0, v6

    float-to-int p0, v0

    add-int/2addr v2, p0

    add-int/2addr v3, v2

    invoke-virtual {p2, v2, v3}, La/e/b/h/d;->F(II)V

    invoke-static {p2, p1, p3}, La/e/b/h/l/h;->b(La/e/b/h/d;La/e/b/h/l/b$b;Z)V

    :cond_4
    return-void
.end method

.method public static e(La/e/b/h/l/b$b;La/e/b/h/d;)V
    .locals 6

    .line 1
    iget v0, p1, La/e/b/h/d;->c0:F

    .line 2
    iget-object v1, p1, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v2, p1, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->c()I

    move-result v2

    iget-object v3, p1, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v1

    iget-object v4, p1, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    sub-int v4, v2, v4

    const/high16 v5, 0x3f000000    # 0.5f

    if-ne v1, v2, :cond_0

    move v0, v5

    goto :goto_0

    :cond_0
    move v1, v3

    move v2, v4

    :goto_0
    invoke-virtual {p1}, La/e/b/h/d;->l()I

    move-result v3

    sub-int v4, v2, v1

    sub-int/2addr v4, v3

    if-le v1, v2, :cond_1

    sub-int v4, v1, v2

    sub-int/2addr v4, v3

    :cond_1
    int-to-float v4, v4

    mul-float/2addr v0, v4

    add-float/2addr v0, v5

    float-to-int v0, v0

    add-int v4, v1, v0

    add-int v5, v4, v3

    if-le v1, v2, :cond_2

    sub-int v4, v1, v0

    sub-int v5, v4, v3

    :cond_2
    invoke-virtual {p1, v4, v5}, La/e/b/h/d;->G(II)V

    invoke-static {p1, p0}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    return-void
.end method

.method public static f(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;)V
    .locals 7

    .line 1
    iget v0, p2, La/e/b/h/d;->c0:F

    .line 2
    iget-object v1, p2, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v2, p2, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    add-int/2addr v2, v1

    iget-object v1, p2, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v1

    iget-object v3, p2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    sub-int/2addr v1, v3

    if-lt v1, v2, :cond_4

    invoke-virtual {p2}, La/e/b/h/d;->l()I

    move-result v3

    .line 3
    iget v4, p2, La/e/b/h/d;->e0:I

    const/16 v5, 0x8

    const/high16 v6, 0x3f000000    # 0.5f

    if-eq v4, v5, :cond_3

    .line 4
    iget v4, p2, La/e/b/h/d;->o:I

    const/4 v5, 0x2

    if-ne v4, v5, :cond_1

    instance-of v3, p0, La/e/b/h/e;

    if-eqz v3, :cond_0

    goto :goto_0

    .line 5
    :cond_0
    iget-object p0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 6
    :goto_0
    invoke-virtual {p0}, La/e/b/h/d;->l()I

    move-result p0

    mul-float v3, v0, v6

    int-to-float p0, p0

    mul-float/2addr v3, p0

    float-to-int v3, v3

    goto :goto_1

    :cond_1
    if-nez v4, :cond_2

    sub-int v3, v1, v2

    :cond_2
    :goto_1
    iget p0, p2, La/e/b/h/d;->t:I

    invoke-static {p0, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    iget p0, p2, La/e/b/h/d;->u:I

    if-lez p0, :cond_3

    invoke-static {p0, v3}, Ljava/lang/Math;->min(II)I

    move-result v3

    :cond_3
    sub-int/2addr v1, v2

    sub-int/2addr v1, v3

    int-to-float p0, v1

    mul-float/2addr v0, p0

    add-float/2addr v0, v6

    float-to-int p0, v0

    add-int/2addr v2, p0

    add-int/2addr v3, v2

    invoke-virtual {p2, v2, v3}, La/e/b/h/d;->G(II)V

    invoke-static {p2, p1}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    :cond_4
    return-void
.end method

.method public static g(La/e/b/h/d;La/e/b/h/l/b$b;)V
    .locals 13

    sget-object v0, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    instance-of v1, p0, La/e/b/h/e;

    const/4 v2, 0x0

    if-nez v1, :cond_0

    invoke-virtual {p0}, La/e/b/h/d;->y()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {p0}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, La/e/b/h/l/b$a;

    invoke-direct {v1}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {p0, p1, v1, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_0
    sget-object v1, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    invoke-virtual {p0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v1

    sget-object v3, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    invoke-virtual {p0, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v3

    invoke-virtual {v1}, La/e/b/h/c;->c()I

    move-result v4

    invoke-virtual {v3}, La/e/b/h/c;->c()I

    move-result v5

    .line 1
    iget-object v6, v1, La/e/b/h/c;->a:Ljava/util/HashSet;

    const/4 v7, 0x0

    const/16 v8, 0x8

    const/4 v9, 0x1

    if-eqz v6, :cond_c

    .line 2
    iget-boolean v1, v1, La/e/b/h/c;->c:Z

    if-eqz v1, :cond_c

    .line 3
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_c

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, La/e/b/h/c;

    iget-object v10, v6, La/e/b/h/c;->d:La/e/b/h/d;

    invoke-static {v10}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v11

    invoke-virtual {v10}, La/e/b/h/d;->y()Z

    move-result v12

    if-eqz v12, :cond_2

    if-eqz v11, :cond_2

    new-instance v12, La/e/b/h/l/b$a;

    invoke-direct {v12}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {v10, p1, v12, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_2
    invoke-virtual {v10}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v12

    if-ne v12, v0, :cond_8

    if-eqz v11, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v10}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v11

    if-ne v11, v0, :cond_1

    iget v11, v10, La/e/b/h/d;->u:I

    if-ltz v11, :cond_1

    iget v11, v10, La/e/b/h/d;->t:I

    if-ltz v11, :cond_1

    .line 4
    iget v11, v10, La/e/b/h/d;->e0:I

    if-eq v11, v8, :cond_4

    .line 5
    iget v11, v10, La/e/b/h/d;->o:I

    if-nez v11, :cond_1

    .line 6
    iget v11, v10, La/e/b/h/d;->U:F

    cmpl-float v11, v11, v7

    if-nez v11, :cond_1

    .line 7
    :cond_4
    invoke-virtual {v10}, La/e/b/h/d;->x()Z

    move-result v11

    if-nez v11, :cond_1

    .line 8
    iget-boolean v11, v10, La/e/b/h/d;->C:Z

    if-nez v11, :cond_1

    .line 9
    iget-object v11, v10, La/e/b/h/d;->G:La/e/b/h/c;

    if-ne v6, v11, :cond_5

    iget-object v11, v10, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v11, v11, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v11, :cond_5

    .line 10
    iget-boolean v11, v11, La/e/b/h/c;->c:Z

    if-nez v11, :cond_6

    .line 11
    :cond_5
    iget-object v11, v10, La/e/b/h/d;->I:La/e/b/h/c;

    if-ne v6, v11, :cond_7

    iget-object v6, v10, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_7

    .line 12
    iget-boolean v6, v6, La/e/b/h/c;->c:Z

    if-eqz v6, :cond_7

    :cond_6
    move v6, v9

    goto :goto_1

    :cond_7
    move v6, v2

    :goto_1
    if-eqz v6, :cond_1

    .line 13
    invoke-virtual {v10}, La/e/b/h/d;->x()Z

    move-result v6

    if-nez v6, :cond_1

    invoke-static {p0, p1, v10}, La/e/b/h/l/h;->f(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;)V

    goto :goto_0

    :cond_8
    :goto_2
    invoke-virtual {v10}, La/e/b/h/d;->y()Z

    move-result v11

    if-eqz v11, :cond_9

    goto/16 :goto_0

    :cond_9
    iget-object v11, v10, La/e/b/h/d;->G:La/e/b/h/c;

    if-ne v6, v11, :cond_a

    iget-object v12, v10, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v12, v12, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v12, :cond_a

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v6

    add-int/2addr v6, v4

    invoke-virtual {v10}, La/e/b/h/d;->l()I

    move-result v11

    add-int/2addr v11, v6

    invoke-virtual {v10, v6, v11}, La/e/b/h/d;->G(II)V

    goto :goto_3

    :cond_a
    iget-object v11, v10, La/e/b/h/d;->I:La/e/b/h/c;

    if-ne v6, v11, :cond_b

    iget-object v12, v11, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v12, :cond_b

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v6

    sub-int v6, v4, v6

    invoke-virtual {v10}, La/e/b/h/d;->l()I

    move-result v11

    sub-int v11, v6, v11

    invoke-virtual {v10, v11, v6}, La/e/b/h/d;->G(II)V

    :goto_3
    invoke-static {v10, p1}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    goto/16 :goto_0

    :cond_b
    iget-object v11, v10, La/e/b/h/d;->G:La/e/b/h/c;

    if-ne v6, v11, :cond_1

    iget-object v6, v10, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_1

    .line 14
    iget-boolean v6, v6, La/e/b/h/c;->c:Z

    if-eqz v6, :cond_1

    .line 15
    invoke-static {p1, v10}, La/e/b/h/l/h;->e(La/e/b/h/l/b$b;La/e/b/h/d;)V

    goto/16 :goto_0

    :cond_c
    instance-of v1, p0, La/e/b/h/f;

    if-eqz v1, :cond_d

    return-void

    .line 16
    :cond_d
    iget-object v1, v3, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v1, :cond_19

    .line 17
    iget-boolean v3, v3, La/e/b/h/c;->c:Z

    if-eqz v3, :cond_19

    .line 18
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_e
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_19

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v4, v3, La/e/b/h/c;->d:La/e/b/h/d;

    invoke-static {v4}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v6

    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v10

    if-eqz v10, :cond_f

    if-eqz v6, :cond_f

    new-instance v10, La/e/b/h/l/b$a;

    invoke-direct {v10}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {v4, p1, v10, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_f
    iget-object v10, v4, La/e/b/h/d;->G:La/e/b/h/c;

    if-ne v3, v10, :cond_10

    iget-object v10, v4, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v10, :cond_10

    .line 19
    iget-boolean v10, v10, La/e/b/h/c;->c:Z

    if-nez v10, :cond_11

    .line 20
    :cond_10
    iget-object v10, v4, La/e/b/h/d;->I:La/e/b/h/c;

    if-ne v3, v10, :cond_12

    iget-object v10, v4, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v10, v10, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v10, :cond_12

    .line 21
    iget-boolean v10, v10, La/e/b/h/c;->c:Z

    if-eqz v10, :cond_12

    :cond_11
    move v10, v9

    goto :goto_5

    :cond_12
    move v10, v2

    .line 22
    :goto_5
    invoke-virtual {v4}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v11

    if-ne v11, v0, :cond_15

    if-eqz v6, :cond_13

    goto :goto_6

    :cond_13
    invoke-virtual {v4}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v3

    if-ne v3, v0, :cond_e

    iget v3, v4, La/e/b/h/d;->u:I

    if-ltz v3, :cond_e

    iget v3, v4, La/e/b/h/d;->t:I

    if-ltz v3, :cond_e

    .line 23
    iget v3, v4, La/e/b/h/d;->e0:I

    if-eq v3, v8, :cond_14

    .line 24
    iget v3, v4, La/e/b/h/d;->o:I

    if-nez v3, :cond_e

    .line 25
    iget v3, v4, La/e/b/h/d;->U:F

    cmpl-float v3, v3, v7

    if-nez v3, :cond_e

    .line 26
    :cond_14
    invoke-virtual {v4}, La/e/b/h/d;->x()Z

    move-result v3

    if-nez v3, :cond_e

    .line 27
    iget-boolean v3, v4, La/e/b/h/d;->C:Z

    if-nez v3, :cond_e

    if-eqz v10, :cond_e

    .line 28
    invoke-virtual {v4}, La/e/b/h/d;->x()Z

    move-result v3

    if-nez v3, :cond_e

    invoke-static {p0, p1, v4}, La/e/b/h/l/h;->f(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/d;)V

    goto :goto_4

    :cond_15
    :goto_6
    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v6

    if-eqz v6, :cond_16

    goto/16 :goto_4

    :cond_16
    iget-object v6, v4, La/e/b/h/d;->G:La/e/b/h/c;

    if-ne v3, v6, :cond_17

    iget-object v11, v4, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v11, v11, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v11, :cond_17

    invoke-virtual {v6}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v5

    invoke-virtual {v4}, La/e/b/h/d;->l()I

    move-result v6

    add-int/2addr v6, v3

    invoke-virtual {v4, v3, v6}, La/e/b/h/d;->G(II)V

    goto :goto_7

    :cond_17
    iget-object v6, v4, La/e/b/h/d;->I:La/e/b/h/c;

    if-ne v3, v6, :cond_18

    iget-object v3, v4, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v3, :cond_18

    invoke-virtual {v6}, La/e/b/h/c;->d()I

    move-result v3

    sub-int v3, v5, v3

    invoke-virtual {v4}, La/e/b/h/d;->l()I

    move-result v6

    sub-int v6, v3, v6

    invoke-virtual {v4, v6, v3}, La/e/b/h/d;->G(II)V

    :goto_7
    invoke-static {v4, p1}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    goto/16 :goto_4

    :cond_18
    if-eqz v10, :cond_e

    invoke-virtual {v4}, La/e/b/h/d;->x()Z

    move-result v3

    if-nez v3, :cond_e

    invoke-static {p1, v4}, La/e/b/h/l/h;->e(La/e/b/h/l/b$b;La/e/b/h/d;)V

    goto/16 :goto_4

    :cond_19
    sget-object v1, La/e/b/h/c$a;->g:La/e/b/h/c$a;

    invoke-virtual {p0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object p0

    .line 29
    iget-object v1, p0, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz v1, :cond_1f

    .line 30
    iget-boolean v1, p0, La/e/b/h/c;->c:Z

    if-eqz v1, :cond_1f

    .line 31
    invoke-virtual {p0}, La/e/b/h/c;->c()I

    move-result v1

    .line 32
    iget-object p0, p0, La/e/b/h/c;->a:Ljava/util/HashSet;

    .line 33
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_1a
    :goto_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1f

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    iget-object v4, v3, La/e/b/h/c;->d:La/e/b/h/d;

    invoke-static {v4}, La/e/b/h/l/h;->a(La/e/b/h/d;)Z

    move-result v5

    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v6

    if-eqz v6, :cond_1b

    if-eqz v5, :cond_1b

    new-instance v6, La/e/b/h/l/b$a;

    invoke-direct {v6}, La/e/b/h/l/b$a;-><init>()V

    invoke-static {v4, p1, v6, v2}, La/e/b/h/e;->X(La/e/b/h/d;La/e/b/h/l/b$b;La/e/b/h/l/b$a;I)Z

    :cond_1b
    invoke-virtual {v4}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v6

    if-ne v6, v0, :cond_1c

    if-eqz v5, :cond_1a

    :cond_1c
    invoke-virtual {v4}, La/e/b/h/d;->y()Z

    move-result v5

    if-eqz v5, :cond_1d

    goto :goto_8

    :cond_1d
    iget-object v5, v4, La/e/b/h/d;->J:La/e/b/h/c;

    if-ne v3, v5, :cond_1a

    .line 34
    iget-boolean v3, v4, La/e/b/h/d;->A:Z

    if-nez v3, :cond_1e

    goto :goto_9

    :cond_1e
    iget v3, v4, La/e/b/h/d;->Y:I

    sub-int v3, v1, v3

    iget v5, v4, La/e/b/h/d;->T:I

    add-int/2addr v5, v3

    iput v3, v4, La/e/b/h/d;->X:I

    iget-object v6, v4, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v6, v3}, La/e/b/h/c;->j(I)V

    iget-object v3, v4, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v3, v5}, La/e/b/h/c;->j(I)V

    iget-object v3, v4, La/e/b/h/d;->J:La/e/b/h/c;

    .line 35
    iput v1, v3, La/e/b/h/c;->b:I

    iput-boolean v9, v3, La/e/b/h/c;->c:Z

    .line 36
    iput-boolean v9, v4, La/e/b/h/d;->k:Z

    .line 37
    :goto_9
    invoke-static {v4, p1}, La/e/b/h/l/h;->g(La/e/b/h/d;La/e/b/h/l/b$b;)V

    goto :goto_8

    :cond_1f
    return-void
.end method
