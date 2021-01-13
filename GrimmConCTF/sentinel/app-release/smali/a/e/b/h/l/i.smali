.class public La/e/b/h/l/i;
.super La/e/b/h/l/o;
.source ""


# direct methods
.method public constructor <init>(La/e/b/h/d;)V
    .locals 1

    invoke-direct {p0, p1}, La/e/b/h/l/o;-><init>(La/e/b/h/d;)V

    iget-object v0, p1, La/e/b/h/d;->d:La/e/b/h/l/k;

    invoke-virtual {v0}, La/e/b/h/l/k;->f()V

    iget-object v0, p1, La/e/b/h/d;->e:La/e/b/h/l/m;

    invoke-virtual {v0}, La/e/b/h/l/m;->f()V

    check-cast p1, La/e/b/h/f;

    .line 1
    iget p1, p1, La/e/b/h/f;->s0:I

    .line 2
    iput p1, p0, La/e/b/h/l/o;->f:I

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 2

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v0, p1, La/e/b/h/l/f;->c:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-boolean v0, p1, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_1

    return-void

    :cond_1
    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/e/b/h/l/f;

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    check-cast v0, La/e/b/h/f;

    const/high16 v1, 0x3f000000    # 0.5f

    iget p1, p1, La/e/b/h/l/f;->g:I

    int-to-float p1, p1

    .line 1
    iget v0, v0, La/e/b/h/f;->o0:F

    mul-float/2addr p1, v0

    add-float/2addr p1, v1

    float-to-int p1, p1

    .line 2
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v0, p1}, La/e/b/h/l/f;->c(I)V

    return-void
.end method

.method public d()V
    .locals 6

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    move-object v1, v0

    check-cast v1, La/e/b/h/f;

    .line 1
    iget v2, v1, La/e/b/h/f;->p0:I

    .line 2
    iget v3, v1, La/e/b/h/f;->q0:I

    .line 3
    iget v1, v1, La/e/b/h/f;->s0:I

    const/4 v4, 0x1

    const/4 v5, -0x1

    if-ne v1, v4, :cond_2

    .line 4
    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    if-eq v2, v5, :cond_0

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iput v2, v0, La/e/b/h/l/f;->f:I

    goto :goto_0

    :cond_0
    if-eq v3, v5, :cond_1

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    neg-int v1, v3

    iput v1, v0, La/e/b/h/l/f;->f:I

    goto :goto_0

    :cond_1
    iput-boolean v4, v1, La/e/b/h/l/f;->b:Z

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_0
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/i;->m(La/e/b/h/l/f;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_2

    :cond_2
    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    if-eq v2, v5, :cond_3

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iput v2, v0, La/e/b/h/l/f;->f:I

    goto :goto_1

    :cond_3
    if-eq v3, v5, :cond_4

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    neg-int v1, v3

    iput v1, v0, La/e/b/h/l/f;->f:I

    goto :goto_1

    :cond_4
    iput-boolean v4, v1, La/e/b/h/l/f;->b:Z

    iget-object v1, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_1
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/i;->m(La/e/b/h/l/f;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    :goto_2
    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {p0, v0}, La/e/b/h/l/i;->m(La/e/b/h/l/f;)V

    return-void
.end method

.method public e()V
    .locals 3

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    move-object v1, v0

    check-cast v1, La/e/b/h/f;

    .line 1
    iget v1, v1, La/e/b/h/f;->s0:I

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    .line 2
    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->g:I

    .line 3
    iput v1, v0, La/e/b/h/d;->W:I

    goto :goto_0

    .line 4
    :cond_0
    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->g:I

    .line 5
    iput v1, v0, La/e/b/h/d;->X:I

    :goto_0
    return-void
.end method

.method public f()V
    .locals 1

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
