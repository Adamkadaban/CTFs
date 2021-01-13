.class public La/e/b/h/f;
.super La/e/b/h/d;
.source ""


# instance fields
.field public o0:F

.field public p0:I

.field public q0:I

.field public r0:La/e/b/h/c;

.field public s0:I

.field public t0:Z


# direct methods
.method public constructor <init>()V
    .locals 4

    invoke-direct {p0}, La/e/b/h/d;-><init>()V

    const/high16 v0, -0x40800000    # -1.0f

    iput v0, p0, La/e/b/h/f;->o0:F

    const/4 v0, -0x1

    iput v0, p0, La/e/b/h/f;->p0:I

    iput v0, p0, La/e/b/h/f;->q0:I

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iput-object v0, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    const/4 v0, 0x0

    iput v0, p0, La/e/b/h/f;->s0:I

    iget-object v1, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    iget-object v1, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v1, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    array-length v1, v1

    :goto_0
    if-ge v0, v1, :cond_0

    iget-object v2, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    iget-object v3, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    aput-object v3, v2, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method


# virtual methods
.method public A()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/f;->t0:Z

    return v0
.end method

.method public O(La/e/b/d;Z)V
    .locals 2

    .line 1
    iget-object p2, p0, La/e/b/h/d;->R:La/e/b/h/d;

    if-nez p2, :cond_0

    return-void

    .line 2
    :cond_0
    iget-object p2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {p1, p2}, La/e/b/d;->o(Ljava/lang/Object;)I

    move-result p1

    iget p2, p0, La/e/b/h/f;->s0:I

    const/4 v0, 0x1

    const/4 v1, 0x0

    if-ne p2, v0, :cond_1

    .line 3
    iput p1, p0, La/e/b/h/d;->W:I

    .line 4
    iput v1, p0, La/e/b/h/d;->X:I

    .line 5
    iget-object p1, p0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 6
    invoke-virtual {p1}, La/e/b/h/d;->l()I

    move-result p1

    invoke-virtual {p0, p1}, La/e/b/h/d;->H(I)V

    invoke-virtual {p0, v1}, La/e/b/h/d;->M(I)V

    goto :goto_0

    .line 7
    :cond_1
    iput v1, p0, La/e/b/h/d;->W:I

    .line 8
    iput p1, p0, La/e/b/h/d;->X:I

    .line 9
    iget-object p1, p0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 10
    invoke-virtual {p1}, La/e/b/h/d;->r()I

    move-result p1

    invoke-virtual {p0, p1}, La/e/b/h/d;->M(I)V

    invoke-virtual {p0, v1}, La/e/b/h/d;->H(I)V

    :goto_0
    return-void
.end method

.method public P(I)V
    .locals 1

    iget-object v0, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    .line 1
    iput p1, v0, La/e/b/h/c;->b:I

    const/4 p1, 0x1

    iput-boolean p1, v0, La/e/b/h/c;->c:Z

    .line 2
    iput-boolean p1, p0, La/e/b/h/f;->t0:Z

    return-void
.end method

.method public Q(I)V
    .locals 3

    iget v0, p0, La/e/b/h/f;->s0:I

    if-ne v0, p1, :cond_0

    return-void

    :cond_0
    iput p1, p0, La/e/b/h/f;->s0:I

    iget-object p1, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    iget p1, p0, La/e/b/h/f;->s0:I

    const/4 v0, 0x1

    if-ne p1, v0, :cond_1

    iget-object p1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    goto :goto_0

    :cond_1
    iget-object p1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    :goto_0
    iput-object p1, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    iget-object p1, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v0, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object p1, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    array-length p1, p1

    const/4 v0, 0x0

    :goto_1
    if-ge v0, p1, :cond_2

    iget-object v1, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    iget-object v2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    aput-object v2, v1, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_2
    return-void
.end method

.method public d(La/e/b/d;Z)V
    .locals 7

    .line 1
    sget-object p2, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    .line 2
    check-cast v0, La/e/b/h/e;

    if-nez v0, :cond_0

    return-void

    :cond_0
    sget-object v1, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-virtual {v0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v1

    sget-object v2, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    invoke-virtual {v0, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    iget-object v3, p0, La/e/b/h/d;->R:La/e/b/h/d;

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v3, :cond_1

    iget-object v3, v3, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v3, v3, v5

    if-ne v3, p2, :cond_1

    move v3, v4

    goto :goto_0

    :cond_1
    move v3, v5

    :goto_0
    iget v6, p0, La/e/b/h/f;->s0:I

    if-nez v6, :cond_3

    sget-object v1, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    invoke-virtual {v0, v1}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v1

    sget-object v2, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    invoke-virtual {v0, v2}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_2

    iget-object v0, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v0, v0, v4

    if-ne v0, p2, :cond_2

    goto :goto_1

    :cond_2
    move v4, v5

    :goto_1
    move v3, v4

    :cond_3
    iget-boolean p2, p0, La/e/b/h/f;->t0:Z

    const/4 v0, -0x1

    const/4 v4, 0x5

    if-eqz p2, :cond_6

    iget-object p2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    .line 3
    iget-boolean v6, p2, La/e/b/h/c;->c:Z

    if-eqz v6, :cond_6

    .line 4
    invoke-virtual {p1, p2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object p2

    iget-object v6, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {v6}, La/e/b/h/c;->c()I

    move-result v6

    invoke-virtual {p1, p2, v6}, La/e/b/d;->e(La/e/b/g;I)V

    iget v6, p0, La/e/b/h/f;->p0:I

    if-eq v6, v0, :cond_4

    if-eqz v3, :cond_5

    invoke-virtual {p1, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    :goto_2
    invoke-virtual {p1, v0, p2, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_3

    :cond_4
    iget v6, p0, La/e/b/h/f;->q0:I

    if-eq v6, v0, :cond_5

    if-eqz v3, :cond_5

    invoke-virtual {p1, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v1

    invoke-virtual {p1, p2, v1, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_2

    :cond_5
    :goto_3
    iput-boolean v5, p0, La/e/b/h/f;->t0:Z

    return-void

    :cond_6
    iget p2, p0, La/e/b/h/f;->p0:I

    const/16 v6, 0x8

    if-eq p2, v0, :cond_7

    iget-object p2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {p1, p2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object p2

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget v1, p0, La/e/b/h/f;->p0:I

    invoke-virtual {p1, p2, v0, v1, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    if-eqz v3, :cond_9

    invoke-virtual {p1, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    :goto_4
    invoke-virtual {p1, v0, p2, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_5

    :cond_7
    iget p2, p0, La/e/b/h/f;->q0:I

    if-eq p2, v0, :cond_8

    iget-object p2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {p1, p2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object p2

    invoke-virtual {p1, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    iget v2, p0, La/e/b/h/f;->q0:I

    neg-int v2, v2

    invoke-virtual {p1, p2, v0, v2, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    if-eqz v3, :cond_9

    invoke-virtual {p1, v1}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v1

    invoke-virtual {p1, p2, v1, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_4

    :cond_8
    iget p2, p0, La/e/b/h/f;->o0:F

    const/high16 v0, -0x40800000    # -1.0f

    cmpl-float p2, p2, v0

    if-eqz p2, :cond_9

    iget-object p2, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    invoke-virtual {p1, p2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object p2

    invoke-virtual {p1, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v1

    iget v2, p0, La/e/b/h/f;->o0:F

    .line 5
    invoke-virtual {p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v3

    .line 6
    iget-object v4, v3, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v4, p2, v0}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object p2, v3, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {p2, v1, v2}, La/e/b/b$a;->j(La/e/b/g;F)V

    .line 7
    invoke-virtual {p1, v3}, La/e/b/d;->c(La/e/b/b;)V

    :cond_9
    :goto_5
    return-void
.end method

.method public e()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public i(La/e/b/h/c$a;)La/e/b/h/c;
    .locals 2

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    packed-switch v0, :pswitch_data_0

    goto :goto_0

    :pswitch_0
    const/4 p1, 0x0

    return-object p1

    :pswitch_1
    iget v0, p0, La/e/b/h/f;->s0:I

    if-nez v0, :cond_0

    iget-object p1, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    return-object p1

    :pswitch_2
    iget v0, p0, La/e/b/h/f;->s0:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    iget-object p1, p0, La/e/b/h/f;->r0:La/e/b/h/c;

    return-object p1

    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_2
        :pswitch_1
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public z()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/f;->t0:Z

    return v0
.end method
