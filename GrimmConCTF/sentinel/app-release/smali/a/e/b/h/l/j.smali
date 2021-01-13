.class public La/e/b/h/l/j;
.super La/e/b/h/l/o;
.source ""


# direct methods
.method public constructor <init>(La/e/b/h/d;)V
    .locals 0

    invoke-direct {p0, p1}, La/e/b/h/l/o;-><init>(La/e/b/h/d;)V

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 6

    iget-object p1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    check-cast p1, La/e/b/h/a;

    .line 1
    iget v0, p1, La/e/b/h/a;->q0:I

    const/4 v1, 0x0

    .line 2
    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    const/4 v3, -0x1

    move v4, v3

    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, La/e/b/h/l/f;

    iget v5, v5, La/e/b/h/l/f;->g:I

    if-eq v4, v3, :cond_1

    if-ge v5, v4, :cond_2

    :cond_1
    move v4, v5

    :cond_2
    if-ge v1, v5, :cond_0

    move v1, v5

    goto :goto_0

    :cond_3
    if-eqz v0, :cond_5

    const/4 v2, 0x2

    if-ne v0, v2, :cond_4

    goto :goto_1

    :cond_4
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    .line 3
    iget p1, p1, La/e/b/h/a;->s0:I

    add-int/2addr v1, p1

    .line 4
    invoke-virtual {v0, v1}, La/e/b/h/l/f;->c(I)V

    goto :goto_2

    :cond_5
    :goto_1
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    .line 5
    iget p1, p1, La/e/b/h/a;->s0:I

    add-int/2addr v4, p1

    .line 6
    invoke-virtual {v0, v4}, La/e/b/h/l/f;->c(I)V

    :goto_2
    return-void
.end method

.method public d()V
    .locals 7

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    instance-of v1, v0, La/e/b/h/a;

    if-eqz v1, :cond_a

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    const/4 v2, 0x1

    iput-boolean v2, v1, La/e/b/h/l/f;->b:Z

    check-cast v0, La/e/b/h/a;

    .line 1
    iget v3, v0, La/e/b/h/a;->q0:I

    .line 2
    iget-boolean v4, v0, La/e/b/h/a;->r0:Z

    const/16 v5, 0x8

    const/4 v6, 0x0

    if-eqz v3, :cond_7

    if-eq v3, v2, :cond_5

    const/4 v2, 0x2

    if-eq v3, v2, :cond_2

    const/4 v2, 0x3

    if-eq v3, v2, :cond_0

    goto/16 :goto_9

    .line 3
    :cond_0
    sget-object v2, La/e/b/h/l/f$a;->h:La/e/b/h/l/f$a;

    iput-object v2, v1, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    :goto_0
    iget v1, v0, La/e/b/h/h;->p0:I

    if-ge v6, v1, :cond_4

    iget-object v1, v0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v1, v1, v6

    if-nez v4, :cond_1

    .line 4
    iget v2, v1, La/e/b/h/d;->e0:I

    if-ne v2, v5, :cond_1

    goto :goto_1

    .line 5
    :cond_1
    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_1
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_2
    sget-object v2, La/e/b/h/l/f$a;->g:La/e/b/h/l/f$a;

    iput-object v2, v1, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    :goto_2
    iget v1, v0, La/e/b/h/h;->p0:I

    if-ge v6, v1, :cond_4

    iget-object v1, v0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v1, v1, v6

    if-nez v4, :cond_3

    .line 6
    iget v2, v1, La/e/b/h/d;->e0:I

    if-ne v2, v5, :cond_3

    goto :goto_3

    .line 7
    :cond_3
    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_3
    add-int/lit8 v6, v6, 0x1

    goto :goto_2

    :cond_4
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/j;->m(La/e/b/h/l/f;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    goto :goto_8

    :cond_5
    sget-object v2, La/e/b/h/l/f$a;->f:La/e/b/h/l/f$a;

    iput-object v2, v1, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    :goto_4
    iget v1, v0, La/e/b/h/h;->p0:I

    if-ge v6, v1, :cond_9

    iget-object v1, v0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v1, v1, v6

    if-nez v4, :cond_6

    .line 8
    iget v2, v1, La/e/b/h/d;->e0:I

    if-ne v2, v5, :cond_6

    goto :goto_5

    .line 9
    :cond_6
    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_5
    add-int/lit8 v6, v6, 0x1

    goto :goto_4

    :cond_7
    sget-object v2, La/e/b/h/l/f$a;->e:La/e/b/h/l/f$a;

    iput-object v2, v1, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    :goto_6
    iget v1, v0, La/e/b/h/h;->p0:I

    if-ge v6, v1, :cond_9

    iget-object v1, v0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v1, v1, v6

    if-nez v4, :cond_8

    .line 10
    iget v2, v1, La/e/b/h/d;->e0:I

    if-ne v2, v5, :cond_8

    goto :goto_7

    .line 11
    :cond_8
    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_7
    add-int/lit8 v6, v6, 0x1

    goto :goto_6

    :cond_9
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/j;->m(La/e/b/h/l/f;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    :goto_8
    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/j;->m(La/e/b/h/l/f;)V

    :cond_a
    :goto_9
    return-void
.end method

.method public e()V
    .locals 3

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    instance-of v1, v0, La/e/b/h/a;

    if-eqz v1, :cond_2

    move-object v1, v0

    check-cast v1, La/e/b/h/a;

    .line 1
    iget v1, v1, La/e/b/h/a;->q0:I

    if-eqz v1, :cond_1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->g:I

    .line 3
    iput v1, v0, La/e/b/h/d;->X:I

    goto :goto_1

    .line 4
    :cond_1
    :goto_0
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->g:I

    .line 5
    iput v1, v0, La/e/b/h/d;->W:I

    :cond_2
    :goto_1
    return-void
.end method

.method public f()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/o;->c:La/e/b/h/l/l;

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/l/f;->b()V

    return-void
.end method

.method public k()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final m(La/e/b/h/l/f;)V
    .locals 1

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {p1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method
