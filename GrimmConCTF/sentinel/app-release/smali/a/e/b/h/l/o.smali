.class public abstract La/e/b/h/l/o;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/e/b/h/l/d;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/h/l/o$a;
    }
.end annotation


# instance fields
.field public a:I

.field public b:La/e/b/h/d;

.field public c:La/e/b/h/l/l;

.field public d:La/e/b/h/d$a;

.field public e:La/e/b/h/l/g;

.field public f:I

.field public g:Z

.field public h:La/e/b/h/l/f;

.field public i:La/e/b/h/l/f;

.field public j:La/e/b/h/l/o$a;


# direct methods
.method public constructor <init>(La/e/b/h/d;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, La/e/b/h/l/g;

    invoke-direct {v0, p0}, La/e/b/h/l/g;-><init>(La/e/b/h/l/o;)V

    iput-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    const/4 v0, 0x0

    iput v0, p0, La/e/b/h/l/o;->f:I

    iput-boolean v0, p0, La/e/b/h/l/o;->g:Z

    new-instance v0, La/e/b/h/l/f;

    invoke-direct {v0, p0}, La/e/b/h/l/f;-><init>(La/e/b/h/l/o;)V

    iput-object v0, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    new-instance v0, La/e/b/h/l/f;

    invoke-direct {v0, p0}, La/e/b/h/l/f;-><init>(La/e/b/h/l/o;)V

    iput-object v0, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    sget-object v0, La/e/b/h/l/o$a;->b:La/e/b/h/l/o$a;

    iput-object v0, p0, La/e/b/h/l/o;->j:La/e/b/h/l/o$a;

    iput-object p1, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/l/d;)V
    .locals 0

    return-void
.end method

.method public final b(La/e/b/h/l/f;La/e/b/h/l/f;I)V
    .locals 1

    iget-object v0, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput p3, p1, La/e/b/h/l/f;->f:I

    iget-object p2, p2, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final c(La/e/b/h/l/f;La/e/b/h/l/f;ILa/e/b/h/l/g;)V
    .locals 2

    iget-object v0, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p1, La/e/b/h/l/f;->l:Ljava/util/List;

    iget-object v1, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iput p3, p1, La/e/b/h/l/f;->h:I

    iput-object p4, p1, La/e/b/h/l/f;->i:La/e/b/h/l/g;

    iget-object p2, p2, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object p2, p4, La/e/b/h/l/f;->k:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public abstract d()V
.end method

.method public abstract e()V
.end method

.method public abstract f()V
.end method

.method public final g(II)I
    .locals 1

    if-nez p2, :cond_1

    iget-object p2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v0, p2, La/e/b/h/d;->r:I

    iget p2, p2, La/e/b/h/d;->q:I

    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    move-result p2

    if-lez v0, :cond_0

    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    move-result p2

    :cond_0
    if-eq p2, p1, :cond_3

    goto :goto_0

    :cond_1
    iget-object p2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget v0, p2, La/e/b/h/d;->u:I

    iget p2, p2, La/e/b/h/d;->t:I

    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    move-result p2

    if-lez v0, :cond_2

    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    move-result p2

    :cond_2
    if-eq p2, p1, :cond_3

    :goto_0
    move p1, p2

    :cond_3
    return p1
.end method

.method public final h(La/e/b/h/c;)La/e/b/h/l/f;
    .locals 3

    iget-object p1, p1, La/e/b/h/c;->f:La/e/b/h/c;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    iget-object v1, p1, La/e/b/h/c;->d:La/e/b/h/d;

    iget-object p1, p1, La/e/b/h/c;->e:La/e/b/h/c$a;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 v2, 0x1

    if-eq p1, v2, :cond_5

    const/4 v2, 0x2

    if-eq p1, v2, :cond_4

    const/4 v2, 0x3

    if-eq p1, v2, :cond_3

    const/4 v2, 0x4

    if-eq p1, v2, :cond_2

    const/4 v2, 0x5

    if-eq p1, v2, :cond_1

    goto :goto_2

    :cond_1
    iget-object p1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, p1, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    goto :goto_2

    :cond_2
    iget-object p1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    goto :goto_0

    :cond_3
    iget-object p1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    :goto_0
    iget-object v0, p1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    goto :goto_2

    :cond_4
    iget-object p1, v1, La/e/b/h/d;->e:La/e/b/h/l/m;

    goto :goto_1

    :cond_5
    iget-object p1, v1, La/e/b/h/d;->d:La/e/b/h/l/k;

    :goto_1
    iget-object v0, p1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    :goto_2
    return-object v0
.end method

.method public final i(La/e/b/h/c;I)La/e/b/h/l/f;
    .locals 2

    iget-object v0, p1, La/e/b/h/c;->f:La/e/b/h/c;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    iget-object v0, v0, La/e/b/h/c;->d:La/e/b/h/d;

    if-nez p2, :cond_1

    iget-object p2, v0, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_0

    :cond_1
    iget-object p2, v0, La/e/b/h/d;->e:La/e/b/h/l/m;

    :goto_0
    iget-object p1, p1, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object p1, p1, La/e/b/h/c;->e:La/e/b/h/c$a;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_3

    const/4 v0, 0x2

    if-eq p1, v0, :cond_3

    const/4 v0, 0x3

    if-eq p1, v0, :cond_2

    const/4 v0, 0x4

    if-eq p1, v0, :cond_2

    goto :goto_1

    :cond_2
    iget-object v1, p2, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    goto :goto_1

    :cond_3
    iget-object v1, p2, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    :goto_1
    return-object v1
.end method

.method public j()J
    .locals 2

    iget-object v0, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v1, v0, La/e/b/h/l/f;->j:Z

    if-eqz v1, :cond_0

    iget v0, v0, La/e/b/h/l/f;->g:I

    int-to-long v0, v0

    return-wide v0

    :cond_0
    const-wide/16 v0, 0x0

    return-wide v0
.end method

.method public abstract k()Z
.end method

.method public l(La/e/b/h/c;La/e/b/h/c;I)V
    .locals 10

    invoke-virtual {p0, p1}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v0

    invoke-virtual {p0, p2}, La/e/b/h/l/o;->h(La/e/b/h/c;)La/e/b/h/l/f;

    move-result-object v1

    iget-boolean v2, v0, La/e/b/h/l/f;->j:Z

    if-eqz v2, :cond_f

    iget-boolean v2, v1, La/e/b/h/l/f;->j:Z

    if-nez v2, :cond_0

    goto/16 :goto_8

    :cond_0
    iget v2, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {p1}, La/e/b/h/c;->d()I

    move-result p1

    add-int/2addr p1, v2

    iget v2, v1, La/e/b/h/l/f;->g:I

    invoke-virtual {p2}, La/e/b/h/c;->d()I

    move-result p2

    sub-int/2addr v2, p2

    sub-int p2, v2, p1

    iget-object v3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v4, v3, La/e/b/h/l/f;->j:Z

    const/high16 v5, 0x3f000000    # 0.5f

    if-nez v4, :cond_a

    iget-object v4, p0, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    sget-object v6, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    if-ne v4, v6, :cond_a

    .line 1
    iget v4, p0, La/e/b/h/l/o;->a:I

    if-eqz v4, :cond_9

    const/4 v7, 0x1

    if-eq v4, v7, :cond_8

    const/4 v3, 0x2

    if-eq v4, v3, :cond_5

    const/4 v3, 0x3

    if-eq v4, v3, :cond_1

    goto/16 :goto_6

    :cond_1
    iget-object v4, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    iget-object v8, v4, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v9, v8, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v9, v6, :cond_2

    iget v8, v8, La/e/b/h/l/o;->a:I

    if-ne v8, v3, :cond_2

    iget-object v4, v4, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v8, v4, La/e/b/h/l/o;->d:La/e/b/h/d$a;

    if-ne v8, v6, :cond_2

    iget v4, v4, La/e/b/h/l/o;->a:I

    if-ne v4, v3, :cond_2

    goto :goto_6

    :cond_2
    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    if-nez p3, :cond_3

    iget-object v3, v3, La/e/b/h/d;->e:La/e/b/h/l/m;

    goto :goto_0

    :cond_3
    iget-object v3, v3, La/e/b/h/d;->d:La/e/b/h/l/k;

    :goto_0
    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v4, v3, La/e/b/h/l/f;->j:Z

    if-eqz v4, :cond_a

    iget-object v4, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 2
    iget v4, v4, La/e/b/h/d;->U:F

    if-ne p3, v7, :cond_4

    .line 3
    iget v3, v3, La/e/b/h/l/f;->g:I

    int-to-float v3, v3

    div-float/2addr v3, v4

    add-float/2addr v3, v5

    float-to-int v3, v3

    goto :goto_1

    :cond_4
    iget v3, v3, La/e/b/h/l/f;->g:I

    int-to-float v3, v3

    mul-float/2addr v4, v3

    add-float/2addr v4, v5

    float-to-int v3, v4

    :goto_1
    iget-object v4, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    goto :goto_5

    :cond_5
    iget-object v3, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    .line 4
    iget-object v3, v3, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v3, :cond_a

    if-nez p3, :cond_6

    .line 5
    iget-object v3, v3, La/e/b/h/d;->d:La/e/b/h/l/k;

    goto :goto_2

    :cond_6
    iget-object v3, v3, La/e/b/h/d;->e:La/e/b/h/l/m;

    :goto_2
    iget-object v4, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v4, v4, La/e/b/h/l/f;->j:Z

    if-eqz v4, :cond_a

    iget-object v4, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    if-nez p3, :cond_7

    iget v4, v4, La/e/b/h/d;->s:F

    goto :goto_3

    :cond_7
    iget v4, v4, La/e/b/h/d;->v:F

    :goto_3
    iget-object v3, v3, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget v3, v3, La/e/b/h/l/f;->g:I

    int-to-float v3, v3

    mul-float/2addr v3, v4

    add-float/2addr v3, v5

    float-to-int v3, v3

    goto :goto_4

    :cond_8
    iget v3, v3, La/e/b/h/l/g;->m:I

    invoke-virtual {p0, v3, p3}, La/e/b/h/l/o;->g(II)I

    move-result v3

    iget-object v4, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-static {v3, p2}, Ljava/lang/Math;->min(II)I

    move-result v3

    goto :goto_5

    :cond_9
    move v3, p2

    :goto_4
    iget-object v4, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    invoke-virtual {p0, v3, p3}, La/e/b/h/l/o;->g(II)I

    move-result v3

    :goto_5
    invoke-virtual {v4, v3}, La/e/b/h/l/g;->c(I)V

    .line 6
    :cond_a
    :goto_6
    iget-object v3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget-boolean v4, v3, La/e/b/h/l/f;->j:Z

    if-nez v4, :cond_b

    return-void

    :cond_b
    iget v3, v3, La/e/b/h/l/f;->g:I

    if-ne v3, p2, :cond_c

    iget-object p2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    invoke-virtual {p2, p1}, La/e/b/h/l/f;->c(I)V

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    invoke-virtual {p1, v2}, La/e/b/h/l/f;->c(I)V

    return-void

    :cond_c
    iget-object p2, p0, La/e/b/h/l/o;->b:La/e/b/h/d;

    if-nez p3, :cond_d

    .line 7
    iget p2, p2, La/e/b/h/d;->b0:F

    goto :goto_7

    .line 8
    :cond_d
    iget p2, p2, La/e/b/h/d;->c0:F

    :goto_7
    if-ne v0, v1, :cond_e

    .line 9
    iget p1, v0, La/e/b/h/l/f;->g:I

    iget v2, v1, La/e/b/h/l/f;->g:I

    move p2, v5

    :cond_e
    sub-int/2addr v2, p1

    iget-object p3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget p3, p3, La/e/b/h/l/f;->g:I

    sub-int/2addr v2, p3

    iget-object p3, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    int-to-float p1, p1

    add-float/2addr p1, v5

    int-to-float v0, v2

    mul-float/2addr v0, p2

    add-float/2addr v0, p1

    float-to-int p1, v0

    invoke-virtual {p3, p1}, La/e/b/h/l/f;->c(I)V

    iget-object p1, p0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-object p2, p0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget p2, p2, La/e/b/h/l/f;->g:I

    iget-object p3, p0, La/e/b/h/l/o;->e:La/e/b/h/l/g;

    iget p3, p3, La/e/b/h/l/f;->g:I

    add-int/2addr p2, p3

    invoke-virtual {p1, p2}, La/e/b/h/l/f;->c(I)V

    :cond_f
    :goto_8
    return-void
.end method
