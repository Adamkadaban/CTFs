.class public La/e/b/h/l/m;
.super La/e/b/h/l/o;
.source ""


# instance fields
.field public k:La/e/b/h/l/f;

.field public l:La/e/b/h/l/g;


# direct methods
.method public constructor <init>(La/e/b/h/d;)V
    .locals 2

    invoke-direct {p0, p1}, La/e/b/h/l/o;-><init>(La/e/b/h/d;)V

    new-instance p1, La/e/b/h/l/f;

    invoke-direct {p1, p0}, La/e/b/h/l/f;-><init>(La/e/b/h/l/o;)V

    iput-object p1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    sget-object v1, La/e/b/h/l/f$a;->g:La/e/b/h/l/f$a;

    iput-object v1, v0, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    sget-object v1, La/e/b/h/l/f$a;->h:La/e/b/h/l/f$a;

    iput-object v1, v0, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    sget-object v0, La/e/b/h/l/f$a;->i:La/e/b/h/l/f$a;

    iput-object v0, p1, La/e/b/h/l/f;->e:La/e/b/h/l/f$a;

    const/4 p1, 0x1

    iput p1, p0, La/e/b/h/l/o;->f:I

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 8

    sget-object p1, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    iget-object v0, p0, La/e/b/h/l/o;->j:La/e/b/h/l/o$a;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x3

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eq v0, v3, :cond_1

    if-eq v0, v2, :cond_1

    if-eq v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, p1, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p1, p1, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p0, v0, p1, v3}, La/e/b/h/l/o;->l(La/e/b/h/c;La/e/b/h/c;I)V

    return-void

    :cond_1
    :goto_0
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v4, v0, La/e/b/h/l/f;->c:Z

    const/high16 v5, 0x3f000000    # 0.5f

    const/4 v6, 0x0

    if-eqz v4, :cond_6

    iget-boolean v4, v0, La/e/b/h/l/f;->j:Z

    if-nez v4, :cond_6

    iget-object v4, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v4, p1, :cond_6

    iget-object v4, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v7, v4, La/e/b/h/d;->o:I

    if-eq v7, v2, :cond_5

    if-eq v7, v1, :cond_2

    goto :goto_3

    :cond_2
    iget-object v0, v4, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v1, v0, La/e/b/h/l/f;->j:Z

    if-eqz v1, :cond_6

    .line 1
    iget v1, v4, La/e/b/h/d;->V:I

    const/4 v2, -0x1

    if-eq v1, v2, :cond_4

    if-eqz v1, :cond_3

    if-eq v1, v3, :cond_4

    move v0, v6

    goto :goto_2

    .line 2
    :cond_3
    iget v0, v0, La/e/b/h/l/f;->g:I

    int-to-float v0, v0

    .line 3
    iget v1, v4, La/e/b/h/d;->U:F

    mul-float/2addr v0, v1

    goto :goto_1

    .line 4
    :cond_4
    iget v0, v0, La/e/b/h/l/f;->g:I

    int-to-float v0, v0

    .line 5
    iget v1, v4, La/e/b/h/d;->U:F

    div-float/2addr v0, v1

    :goto_1
    add-float/2addr v0, v5

    float-to-int v0, v0

    .line 6
    :goto_2
    iget-object v1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v1, v0}, La/e/b/h/l/g;->c(I)V

    goto :goto_3

    .line 7
    :cond_5
    iget-object v1, v4, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_6

    .line 8
    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v2, v1, La/e/b/h/l/f;->j:Z

    if-eqz v2, :cond_6

    iget v2, v4, La/e/b/h/d;->v:F

    iget v1, v1, La/e/b/h/l/f;->g:I

    int-to-float v1, v1

    mul-float/2addr v1, v2

    add-float/2addr v1, v5

    float-to-int v1, v1

    invoke-virtual {v0, v1}, La/e/b/h/l/g;->c(I)V

    :cond_6
    :goto_3
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v1, v0, La/e/b/h/l/f;->c:Z

    if-eqz v1, :cond_e

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v2, v1, La/e/b/h/l/f;->c:Z

    if-nez v2, :cond_7

    goto/16 :goto_6

    :cond_7
    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_8

    iget-boolean v0, v1, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_8

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_8

    return-void

    :cond_8
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-nez v0, :cond_9

    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v0, p1, :cond_9

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v1, v0, La/e/b/h/d;->n:I

    if-nez v1, :cond_9

    invoke-virtual {v0}, La/e/b/h/d;->x()Z

    move-result v0

    if-nez v0, :cond_9

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/e/b/h/l/f;

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/f;

    iget p1, p1, La/e/b/h/l/f;->g:I

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v2, v1, La/e/b/h/l/f;->f:I

    add-int/2addr p1, v2

    iget v0, v0, La/e/b/h/l/f;->g:I

    iget-object v2, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v2, v2, La/e/b/h/l/f;->f:I

    add-int/2addr v0, v2

    sub-int v2, v0, p1

    invoke-virtual {v1, p1}, La/e/b/h/l/f;->c(I)V

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {p1, v0}, La/e/b/h/l/f;->c(I)V

    iget-object p1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p1, v2}, La/e/b/h/l/g;->c(I)V

    return-void

    :cond_9
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-nez v0, :cond_b

    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v0, p1, :cond_b

    iget p1, p0, La/e/b/h/l/o;->a:I

    if-ne p1, v3, :cond_b

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_b

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_b

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/e/b/h/l/f;

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/f;

    iget p1, p1, La/e/b/h/l/f;->g:I

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    add-int/2addr p1, v1

    iget v0, v0, La/e/b/h/l/f;->g:I

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->f:I

    add-int/2addr v0, v1

    sub-int/2addr v0, p1

    iget-object p1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v1, p1, La/e/b/h/l/g;->m:I

    if-ge v0, v1, :cond_a

    invoke-virtual {p1, v0}, La/e/b/h/l/g;->c(I)V

    goto :goto_4

    :cond_a
    invoke-virtual {p1, v1}, La/e/b/h/l/g;->c(I)V

    :cond_b
    :goto_4
    iget-object p1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean p1, p1, La/e/b/h/l/f;->j:Z

    if-nez p1, :cond_c

    return-void

    :cond_c
    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_e

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-lez p1, :cond_e

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object p1, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/e/b/h/l/f;

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/l/f;

    iget v1, p1, La/e/b/h/l/f;->g:I

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v2, v2, La/e/b/h/l/f;->f:I

    add-int/2addr v2, v1

    iget v3, v0, La/e/b/h/l/f;->g:I

    iget-object v4, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->f:I

    add-int/2addr v4, v3

    iget-object v6, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 9
    iget v6, v6, La/e/b/h/d;->c0:F

    if-ne p1, v0, :cond_d

    move v6, v5

    goto :goto_5

    :cond_d
    move v1, v2

    move v3, v4

    :goto_5
    sub-int/2addr v3, v1

    .line 10
    iget-object p1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget p1, p1, La/e/b/h/l/f;->g:I

    sub-int/2addr v3, p1

    iget-object p1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    int-to-float v0, v1

    add-float/2addr v0, v5

    int-to-float v1, v3

    mul-float/2addr v1, v6

    add-float/2addr v1, v0

    float-to-int v0, v1

    invoke-virtual {p1, v0}, La/e/b/h/l/f;->c(I)V

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    iget-object v1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v1, v1, La/e/b/h/l/f;->g:I

    add-int/2addr v0, v1

    invoke-virtual {p1, v0}, La/e/b/h/l/f;->c(I)V

    :cond_e
    :goto_6
    return-void
.end method

.method public d()V
    .locals 10

    sget-object v0, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-boolean v4, v3, La/e/b/h/d;->a:Z

    if-eqz v4, :cond_0

    iget-object v4, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v3}, La/e/b/h/d;->l()I

    move-result v3

    invoke-virtual {v4, v3}, La/e/b/h/l/g;->c(I)V

    :cond_0
    iget-object v3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v3, v3, La/e/b/h/l/f;->j:Z

    if-nez v3, :cond_3

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    invoke-virtual {v3}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v3

    iput-object v3, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget-boolean v3, v3, La/e/b/h/d;->A:Z

    if-eqz v3, :cond_1

    .line 2
    new-instance v3, La/e/b/h/l/a;

    invoke-direct {v3, p0}, La/e/b/h/l/a;-><init>(La/e/b/h/l/o;)V

    iput-object v3, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    :cond_1
    iget-object v3, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-eq v3, v2, :cond_4

    if-ne v3, v0, :cond_2

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 3
    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_2

    .line 4
    invoke-virtual {v0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v3

    if-ne v3, v1, :cond_2

    invoke-virtual {v0}, La/e/b/h/d;->l()I

    move-result v1

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    sub-int/2addr v1, v2

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    sub-int/2addr v1, v2

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v3, v3, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v4, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v4, v4, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    invoke-virtual {p0, v2, v3, v4}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v2, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v3, v3, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    neg-int v3, v3

    invoke-virtual {p0, v2, v0, v3}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v0, v1}, La/e/b/h/l/g;->c(I)V

    return-void

    :cond_2
    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    invoke-virtual {v1}, La/e/b/h/d;->l()I

    move-result v1

    invoke-virtual {v0, v1}, La/e/b/h/l/g;->c(I)V

    goto :goto_0

    :cond_3
    iget-object v3, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v3, v0, :cond_4

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 5
    iget-object v0, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_4

    .line 6
    invoke-virtual {v0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object v3

    if-ne v3, v1, :cond_4

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v2, v2, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v3, v3, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    invoke-virtual {p0, v1, v2, v3}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v0, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    invoke-virtual {p0, v1, v0, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    return-void

    :cond_4
    :goto_0
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    const/4 v1, 0x0

    const/4 v3, 0x4

    const/4 v4, 0x1

    const/4 v5, 0x2

    const/4 v6, 0x3

    if-eqz v0, :cond_d

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-boolean v7, v0, La/e/b/h/d;->a:Z

    if-eqz v7, :cond_d

    iget-object v2, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v7, v2, v5

    iget-object v7, v7, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v7, :cond_8

    aget-object v2, v2, v6

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v2, :cond_8

    invoke-virtual {v0}, La/e/b/h/d;->x()Z

    move-result v0

    if-eqz v0, :cond_5

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v5

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    iput v1, v0, La/e/b/h/l/f;->f:I

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v6

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    neg-int v1, v1

    iput v1, v0, La/e/b/h/l/f;->f:I

    goto :goto_1

    :cond_5
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v5

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_6

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v5

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    .line 7
    iget-object v3, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 8
    :cond_6
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v6

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_7

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v6

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    .line 9
    iget-object v3, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 10
    :cond_7
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iput-boolean v4, v0, La/e/b/h/l/f;->b:Z

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iput-boolean v4, v0, La/e/b/h/l/f;->b:Z

    :goto_1
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 11
    iget-boolean v1, v0, La/e/b/h/d;->A:Z

    if-eqz v1, :cond_1e

    .line 12
    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    .line 13
    :goto_2
    iget v0, v0, La/e/b/h/d;->Y:I

    .line 14
    invoke-virtual {p0, v1, v2, v0}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    goto/16 :goto_a

    :cond_8
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v4, v2, v5

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_9

    aget-object v0, v2, v5

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_1e

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v5

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    .line 15
    iget-object v3, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 16
    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v2, v2, La/e/b/h/l/f;->g:I

    invoke-virtual {p0, v0, v1, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 17
    iget-boolean v1, v0, La/e/b/h/d;->A:Z

    if-eqz v1, :cond_1e

    .line 18
    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto :goto_2

    :cond_9
    aget-object v4, v2, v6

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_b

    aget-object v0, v2, v6

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_a

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v6

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    .line 19
    iget-object v3, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 20
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v2, v2, La/e/b/h/l/f;->g:I

    neg-int v2, v2

    invoke-virtual {p0, v0, v1, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    :cond_a
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 21
    iget-boolean v1, v0, La/e/b/h/d;->A:Z

    if-eqz v1, :cond_1e

    .line 22
    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto/16 :goto_2

    :cond_b
    aget-object v4, v2, v3

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_c

    aget-object v0, v2, v3

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_1e

    iget-object v2, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    .line 23
    iget-object v3, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v1, v2, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 24
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 25
    iget v2, v2, La/e/b/h/d;->Y:I

    neg-int v2, v2

    .line 26
    invoke-virtual {p0, v0, v1, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v2, v2, La/e/b/h/l/f;->g:I

    invoke-virtual {p0, v0, v1, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    goto/16 :goto_a

    :cond_c
    instance-of v1, v0, La/e/b/h/g;

    if-nez v1, :cond_1e

    .line 27
    iget-object v1, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_1e

    .line 28
    sget-object v1, La/e/b/h/c$a;->h:La/e/b/h/c$a;

    invoke-virtual {v0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v0

    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v0, :cond_1e

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 29
    iget-object v1, v0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 30
    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/d;->t()I

    move-result v0

    invoke-virtual {p0, v2, v1, v0}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v2, v2, La/e/b/h/l/f;->g:I

    invoke-virtual {p0, v0, v1, v2}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 31
    iget-boolean v1, v0, La/e/b/h/d;->A:Z

    if-eqz v1, :cond_1e

    .line 32
    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    goto/16 :goto_2

    :cond_d
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v7, v0, La/e/b/h/l/f;->j:Z

    if-nez v7, :cond_12

    iget-object v7, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v7, v2, :cond_12

    iget-object v7, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v8, v7, La/e/b/h/d;->o:I

    if-eq v8, v5, :cond_10

    if-eq v8, v6, :cond_e

    goto :goto_4

    :cond_e
    invoke-virtual {v7}, La/e/b/h/d;->x()Z

    move-result v0

    if-nez v0, :cond_13

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v7, v0, La/e/b/h/d;->n:I

    if-ne v7, v6, :cond_f

    goto :goto_4

    :cond_f
    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v7, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v7, v7, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v7, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    goto :goto_3

    .line 33
    :cond_10
    iget-object v7, v7, La/e/b/h/d;->R:La/e/b/h/d;

    if-nez v7, :cond_11

    goto :goto_4

    .line 34
    :cond_11
    iget-object v7, v7, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v7, v7, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, v7, La/e/b/h/l/f;->k:Ljava/util/List;

    :goto_3
    iget-object v7, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iput-boolean v4, v0, La/e/b/h/l/f;->b:Z

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v7, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v7, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_12
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    .line 35
    iget-object v7, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v7, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_13

    invoke-virtual {p0, p0}, La/e/b/h/l/m;->a(La/e/b/h/l/d;)V

    .line 36
    :cond_13
    :goto_4
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v7, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v8, v7, v5

    iget-object v8, v8, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v8, :cond_17

    aget-object v7, v7, v6

    iget-object v7, v7, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v7, :cond_17

    invoke-virtual {v0}, La/e/b/h/d;->x()Z

    move-result v0

    if-eqz v0, :cond_14

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v5

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    iput v1, v0, La/e/b/h/l/f;->f:I

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v6

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    neg-int v1, v1

    iput v1, v0, La/e/b/h/l/f;->f:I

    goto :goto_5

    :cond_14
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v5

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v6

    invoke-virtual {p0, v1}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v1

    .line 37
    iget-object v2, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v2, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_15

    invoke-virtual {p0, p0}, La/e/b/h/l/m;->a(La/e/b/h/l/d;)V

    :cond_15
    iget-object v0, v1, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-boolean v0, v1, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_16

    invoke-virtual {p0, p0}, La/e/b/h/l/m;->a(La/e/b/h/l/d;)V

    .line 38
    :cond_16
    sget-object v0, La/e/b/h/l/o$a;->e:La/e/b/h/l/o$a;

    iput-object v0, p0, La/e/b/h/l/o;->j:La/e/b/h/l/o$a;

    :goto_5
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 39
    iget-boolean v0, v0, La/e/b/h/d;->A:Z

    if-eqz v0, :cond_1d

    .line 40
    :goto_6
    iget-object v0, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    :goto_7
    invoke-virtual {p0, v0, v1, v4, v2}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    goto/16 :goto_9

    :cond_17
    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v7, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v8, v7, v5

    iget-object v8, v8, La/e/b/h/c;->f:La/e/b/h/c;

    const/4 v9, 0x0

    if-eqz v8, :cond_19

    aget-object v0, v7, v5

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_1d

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v3, v3, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v3, v3, v5

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    .line 41
    iget-object v5, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v5, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v3, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 42
    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v4, v3}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 43
    iget-boolean v0, v0, La/e/b/h/d;->A:Z

    if-eqz v0, :cond_18

    .line 44
    iget-object v0, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v4, v3}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    :cond_18
    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v0, v2, :cond_1d

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 45
    iget v1, v0, La/e/b/h/d;->U:F

    cmpl-float v1, v1, v9

    if-lez v1, :cond_1d

    .line 46
    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v1, v2, :cond_1d

    goto/16 :goto_8

    :cond_19
    aget-object v5, v7, v6

    iget-object v5, v5, La/e/b/h/c;->f:La/e/b/h/c;

    const/4 v8, -0x1

    if-eqz v5, :cond_1a

    aget-object v0, v7, v6

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_1d

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v6

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    .line 47
    iget-object v3, v1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v2, v1, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 48
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v8, v2}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 49
    iget-boolean v0, v0, La/e/b/h/d;->A:Z

    if-eqz v0, :cond_1d

    goto/16 :goto_6

    .line 50
    :cond_1a
    aget-object v5, v7, v3

    iget-object v5, v5, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v5, :cond_1b

    aget-object v0, v7, v3

    invoke-virtual {p0, v0}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    if-eqz v0, :cond_1d

    iget-object v2, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    .line 51
    iget-object v3, v2, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput v1, v2, La/e/b/h/l/f;->f:I

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 52
    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v8, v2}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v2, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    goto/16 :goto_7

    :cond_1b
    instance-of v1, v0, La/e/b/h/g;

    if-nez v1, :cond_1d

    .line 53
    iget-object v1, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_1d

    .line 54
    iget-object v1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v1, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/d;->t()I

    move-result v0

    invoke-virtual {p0, v3, v1, v0}, La/e/b/h/l/o;->b(La/e/b/h/l/f;La/e/b/h/l/f;I)V

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v4, v3}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 55
    iget-boolean v0, v0, La/e/b/h/d;->A:Z

    if-eqz v0, :cond_1c

    .line 56
    iget-object v0, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-object v3, p0, La/e/b/h/l/m;->l:La/e/b/h/l/g;

    invoke-virtual {p0, v0, v1, v4, v3}, La/e/b/h/l/o;->c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V

    :cond_1c
    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v0, v2, :cond_1d

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 57
    iget v1, v0, La/e/b/h/d;->U:F

    cmpl-float v1, v1, v9

    if-lez v1, :cond_1d

    .line 58
    iget-object v0, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v1, v2, :cond_1d

    :goto_8
    iget-object v0, v0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v0, v0, La/e/b/h/l/f;->k:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v1, v1, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iput-object p0, v0, La/e/b/h/l/f;->a:La/e/b/h/l/d;

    :cond_1d
    :goto_9
    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-object v0, v0, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_1e

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iput-boolean v4, v0, La/e/b/h/l/f;->c:Z

    :cond_1e
    :goto_a
    return-void
.end method

.method public e()V
    .locals 2

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v1, v0, La/e/b/h/l/f;->j:Z

    if-eqz v1, :cond_0

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v0, v0, La/e/b/h/l/f;->g:I

    .line 1
    iput v0, v1, La/e/b/h/d;->X:I

    :cond_0
    return-void
.end method

.method public f()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/l/o;->c:La/e/b/h/l/l;

    iget-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/l/f;->b()V

    iget-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/l/f;->b()V

    iget-object v0, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    invoke-virtual {v0}, La/e/b/h/l/f;->b()V

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {v0}, La/e/b/h/l/f;->b()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/l/o;->g:Z

    return-void
.end method

.method public k()Z
    .locals 3

    iget-object v0, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    const/4 v2, 0x1

    if-ne v0, v1, :cond_1

    iget-object v0, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v0, v0, La/e/b/h/d;->o:I

    if-nez v0, :cond_0

    return v2

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    return v2
.end method

.method public m()V
    .locals 2

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/l/o;->g:Z

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {v1}, La/e/b/h/l/f;->b()V

    iget-object v1, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iput-boolean v0, v1, La/e/b/h/l/f;->j:Z

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {v1}, La/e/b/h/l/f;->b()V

    iget-object v1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iput-boolean v0, v1, La/e/b/h/l/f;->j:Z

    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    invoke-virtual {v1}, La/e/b/h/l/f;->b()V

    iget-object v1, p0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iput-boolean v0, v1, La/e/b/h/l/f;->j:Z

    iget-object v1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iput-boolean v0, v1, La/e/b/h/l/f;->j:Z

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    const-string v0, "VerticalRun "

    invoke-static {v0}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 1
    iget-object v1, v1, La/e/b/h/d;->f0:Ljava/lang/String;

    .line 2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
