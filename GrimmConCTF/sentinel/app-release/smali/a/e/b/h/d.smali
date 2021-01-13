.class public La/e/b/h/d;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/b/h/d$a;
    }
.end annotation


# instance fields
.field public A:Z

.field public B:Z

.field public C:Z

.field public D:I

.field public E:I

.field public F:La/e/b/h/c;

.field public G:La/e/b/h/c;

.field public H:La/e/b/h/c;

.field public I:La/e/b/h/c;

.field public J:La/e/b/h/c;

.field public K:La/e/b/h/c;

.field public L:La/e/b/h/c;

.field public M:La/e/b/h/c;

.field public N:[La/e/b/h/c;

.field public O:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "La/e/b/h/c;",
            ">;"
        }
    .end annotation
.end field

.field public P:[Z

.field public Q:[La/e/b/h/d$a;

.field public R:La/e/b/h/d;

.field public S:I

.field public T:I

.field public U:F

.field public V:I

.field public W:I

.field public X:I

.field public Y:I

.field public Z:I

.field public a:Z

.field public a0:I

.field public b:La/e/b/h/l/c;

.field public b0:F

.field public c:La/e/b/h/l/c;

.field public c0:F

.field public d:La/e/b/h/l/k;

.field public d0:Ljava/lang/Object;

.field public e:La/e/b/h/l/m;

.field public e0:I

.field public f:[Z

.field public f0:Ljava/lang/String;

.field public g:Z

.field public g0:Ljava/lang/String;

.field public h:Z

.field public h0:I

.field public i:Z

.field public i0:I

.field public j:Z

.field public j0:[F

.field public k:Z

.field public k0:[La/e/b/h/d;

.field public l:I

.field public l0:[La/e/b/h/d;

.field public m:I

.field public m0:I

.field public n:I

.field public n0:I

.field public o:I

.field public p:[I

.field public q:I

.field public r:I

.field public s:F

.field public t:I

.field public u:I

.field public v:F

.field public w:I

.field public x:F

.field public y:[I

.field public z:F


# direct methods
.method public constructor <init>()V
    .locals 10

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/d;->a:Z

    const/4 v1, 0x0

    iput-object v1, p0, La/e/b/h/d;->d:La/e/b/h/l/k;

    iput-object v1, p0, La/e/b/h/d;->e:La/e/b/h/l/m;

    const/4 v2, 0x2

    new-array v3, v2, [Z

    fill-array-data v3, :array_0

    iput-object v3, p0, La/e/b/h/d;->f:[Z

    const/4 v3, 0x1

    iput-boolean v3, p0, La/e/b/h/d;->g:Z

    iput-boolean v0, p0, La/e/b/h/d;->h:Z

    iput-boolean v3, p0, La/e/b/h/d;->i:Z

    iput-boolean v0, p0, La/e/b/h/d;->j:Z

    iput-boolean v0, p0, La/e/b/h/d;->k:Z

    const/4 v4, -0x1

    iput v4, p0, La/e/b/h/d;->l:I

    iput v4, p0, La/e/b/h/d;->m:I

    iput v0, p0, La/e/b/h/d;->n:I

    iput v0, p0, La/e/b/h/d;->o:I

    new-array v5, v2, [I

    iput-object v5, p0, La/e/b/h/d;->p:[I

    iput v0, p0, La/e/b/h/d;->q:I

    iput v0, p0, La/e/b/h/d;->r:I

    const/high16 v5, 0x3f800000    # 1.0f

    iput v5, p0, La/e/b/h/d;->s:F

    iput v0, p0, La/e/b/h/d;->t:I

    iput v0, p0, La/e/b/h/d;->u:I

    iput v5, p0, La/e/b/h/d;->v:F

    iput v4, p0, La/e/b/h/d;->w:I

    iput v5, p0, La/e/b/h/d;->x:F

    new-array v5, v2, [I

    fill-array-data v5, :array_1

    iput-object v5, p0, La/e/b/h/d;->y:[I

    const/4 v5, 0x0

    iput v5, p0, La/e/b/h/d;->z:F

    iput-boolean v0, p0, La/e/b/h/d;->A:Z

    iput-boolean v0, p0, La/e/b/h/d;->C:Z

    iput v0, p0, La/e/b/h/d;->D:I

    iput v0, p0, La/e/b/h/d;->E:I

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->F:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->G:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->H:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->I:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->g:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->J:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->i:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->K:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->j:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->L:La/e/b/h/c;

    new-instance v6, La/e/b/h/c;

    sget-object v7, La/e/b/h/c$a;->h:La/e/b/h/c$a;

    invoke-direct {v6, p0, v7}, La/e/b/h/c;-><init>(La/e/b/h/d;La/e/b/h/c$a;)V

    iput-object v6, p0, La/e/b/h/d;->M:La/e/b/h/c;

    const/4 v7, 0x6

    new-array v7, v7, [La/e/b/h/c;

    iget-object v8, p0, La/e/b/h/d;->F:La/e/b/h/c;

    aput-object v8, v7, v0

    iget-object v8, p0, La/e/b/h/d;->H:La/e/b/h/c;

    aput-object v8, v7, v3

    iget-object v8, p0, La/e/b/h/d;->G:La/e/b/h/c;

    aput-object v8, v7, v2

    iget-object v8, p0, La/e/b/h/d;->I:La/e/b/h/c;

    const/4 v9, 0x3

    aput-object v8, v7, v9

    iget-object v8, p0, La/e/b/h/d;->J:La/e/b/h/c;

    const/4 v9, 0x4

    aput-object v8, v7, v9

    const/4 v8, 0x5

    aput-object v6, v7, v8

    iput-object v7, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    iput-object v6, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    new-array v7, v2, [Z

    iput-object v7, p0, La/e/b/h/d;->P:[Z

    new-array v7, v2, [La/e/b/h/d$a;

    sget-object v8, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    aput-object v8, v7, v0

    aput-object v8, v7, v3

    iput-object v7, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    iput-object v1, p0, La/e/b/h/d;->R:La/e/b/h/d;

    iput v0, p0, La/e/b/h/d;->S:I

    iput v0, p0, La/e/b/h/d;->T:I

    iput v5, p0, La/e/b/h/d;->U:F

    iput v4, p0, La/e/b/h/d;->V:I

    iput v0, p0, La/e/b/h/d;->W:I

    iput v0, p0, La/e/b/h/d;->X:I

    iput v0, p0, La/e/b/h/d;->Y:I

    const/high16 v5, 0x3f000000    # 0.5f

    iput v5, p0, La/e/b/h/d;->b0:F

    iput v5, p0, La/e/b/h/d;->c0:F

    iput v0, p0, La/e/b/h/d;->e0:I

    iput-object v1, p0, La/e/b/h/d;->f0:Ljava/lang/String;

    iput-object v1, p0, La/e/b/h/d;->g0:Ljava/lang/String;

    iput v0, p0, La/e/b/h/d;->h0:I

    iput v0, p0, La/e/b/h/d;->i0:I

    new-array v5, v2, [F

    fill-array-data v5, :array_2

    iput-object v5, p0, La/e/b/h/d;->j0:[F

    new-array v5, v2, [La/e/b/h/d;

    aput-object v1, v5, v0

    aput-object v1, v5, v3

    iput-object v5, p0, La/e/b/h/d;->k0:[La/e/b/h/d;

    new-array v2, v2, [La/e/b/h/d;

    aput-object v1, v2, v0

    aput-object v1, v2, v3

    iput-object v2, p0, La/e/b/h/d;->l0:[La/e/b/h/d;

    iput v4, p0, La/e/b/h/d;->m0:I

    iput v4, p0, La/e/b/h/d;->n0:I

    .line 1
    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->K:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->L:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    iget-object v1, p0, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :array_0
    .array-data 1
        0x1t
        0x1t
    .end array-data

    nop

    :array_1
    .array-data 4
        0x7fffffff
        0x7fffffff
    .end array-data

    :array_2
    .array-data 4
        -0x40800000    # -1.0f
        -0x40800000    # -1.0f
    .end array-data
.end method


# virtual methods
.method public A()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/d;->k:Z

    if-nez v0, :cond_1

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    .line 1
    iget-boolean v0, v0, La/e/b/h/c;->c:Z

    if-eqz v0, :cond_0

    .line 2
    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    .line 3
    iget-boolean v0, v0, La/e/b/h/c;->c:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    return v0
.end method

.method public B()V
    .locals 6

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->K:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->L:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    iget-object v0, p0, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->h()V

    const/4 v0, 0x0

    iput-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    const/4 v1, 0x0

    iput v1, p0, La/e/b/h/d;->z:F

    const/4 v2, 0x0

    iput v2, p0, La/e/b/h/d;->S:I

    iput v2, p0, La/e/b/h/d;->T:I

    iput v1, p0, La/e/b/h/d;->U:F

    const/4 v1, -0x1

    iput v1, p0, La/e/b/h/d;->V:I

    iput v2, p0, La/e/b/h/d;->W:I

    iput v2, p0, La/e/b/h/d;->X:I

    iput v2, p0, La/e/b/h/d;->Y:I

    iput v2, p0, La/e/b/h/d;->Z:I

    iput v2, p0, La/e/b/h/d;->a0:I

    const/high16 v3, 0x3f000000    # 0.5f

    iput v3, p0, La/e/b/h/d;->b0:F

    iput v3, p0, La/e/b/h/d;->c0:F

    iget-object v3, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    sget-object v4, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    aput-object v4, v3, v2

    const/4 v5, 0x1

    aput-object v4, v3, v5

    iput-object v0, p0, La/e/b/h/d;->d0:Ljava/lang/Object;

    iput v2, p0, La/e/b/h/d;->e0:I

    iput-object v0, p0, La/e/b/h/d;->g0:Ljava/lang/String;

    iput v2, p0, La/e/b/h/d;->h0:I

    iput v2, p0, La/e/b/h/d;->i0:I

    iget-object v0, p0, La/e/b/h/d;->j0:[F

    const/high16 v3, -0x40800000    # -1.0f

    aput v3, v0, v2

    aput v3, v0, v5

    iput v1, p0, La/e/b/h/d;->l:I

    iput v1, p0, La/e/b/h/d;->m:I

    iget-object v0, p0, La/e/b/h/d;->y:[I

    const v3, 0x7fffffff

    aput v3, v0, v2

    aput v3, v0, v5

    iput v2, p0, La/e/b/h/d;->n:I

    iput v2, p0, La/e/b/h/d;->o:I

    const/high16 v0, 0x3f800000    # 1.0f

    iput v0, p0, La/e/b/h/d;->s:F

    iput v0, p0, La/e/b/h/d;->v:F

    iput v3, p0, La/e/b/h/d;->r:I

    iput v3, p0, La/e/b/h/d;->u:I

    iput v2, p0, La/e/b/h/d;->q:I

    iput v2, p0, La/e/b/h/d;->t:I

    iput v1, p0, La/e/b/h/d;->w:I

    iput v0, p0, La/e/b/h/d;->x:F

    iget-object v0, p0, La/e/b/h/d;->f:[Z

    aput-boolean v5, v0, v2

    aput-boolean v5, v0, v5

    iput-boolean v2, p0, La/e/b/h/d;->C:Z

    iget-object v0, p0, La/e/b/h/d;->P:[Z

    aput-boolean v2, v0, v2

    aput-boolean v2, v0, v5

    iput-boolean v5, p0, La/e/b/h/d;->g:Z

    return-void
.end method

.method public C()V
    .locals 4

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/d;->j:Z

    iput-boolean v0, p0, La/e/b/h/d;->k:Z

    iget-object v1, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    move v2, v0

    :goto_0
    if-ge v2, v1, :cond_0

    iget-object v3, p0, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    .line 1
    iput-boolean v0, v3, La/e/b/h/c;->c:Z

    iput v0, v3, La/e/b/h/c;->b:I

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public D(La/e/b/c;)V
    .locals 0

    iget-object p1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->K:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    iget-object p1, p0, La/e/b/h/d;->L:La/e/b/h/c;

    invoke-virtual {p1}, La/e/b/h/c;->i()V

    return-void
.end method

.method public E(I)V
    .locals 0

    iput p1, p0, La/e/b/h/d;->Y:I

    if-lez p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, La/e/b/h/d;->A:Z

    return-void
.end method

.method public F(II)V
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    .line 1
    iput p1, v0, La/e/b/h/c;->b:I

    const/4 v1, 0x1

    iput-boolean v1, v0, La/e/b/h/c;->c:Z

    .line 2
    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    .line 3
    iput p2, v0, La/e/b/h/c;->b:I

    iput-boolean v1, v0, La/e/b/h/c;->c:Z

    .line 4
    iput p1, p0, La/e/b/h/d;->W:I

    sub-int/2addr p2, p1

    iput p2, p0, La/e/b/h/d;->S:I

    iput-boolean v1, p0, La/e/b/h/d;->j:Z

    return-void
.end method

.method public G(II)V
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    .line 1
    iput p1, v0, La/e/b/h/c;->b:I

    const/4 v1, 0x1

    iput-boolean v1, v0, La/e/b/h/c;->c:Z

    .line 2
    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    .line 3
    iput p2, v0, La/e/b/h/c;->b:I

    iput-boolean v1, v0, La/e/b/h/c;->c:Z

    .line 4
    iput p1, p0, La/e/b/h/d;->X:I

    sub-int/2addr p2, p1

    iput p2, p0, La/e/b/h/d;->T:I

    iget-boolean p2, p0, La/e/b/h/d;->A:Z

    if-eqz p2, :cond_0

    iget-object p2, p0, La/e/b/h/d;->J:La/e/b/h/c;

    iget v0, p0, La/e/b/h/d;->Y:I

    add-int/2addr p1, v0

    invoke-virtual {p2, p1}, La/e/b/h/c;->j(I)V

    :cond_0
    iput-boolean v1, p0, La/e/b/h/d;->k:Z

    return-void
.end method

.method public H(I)V
    .locals 1

    iput p1, p0, La/e/b/h/d;->T:I

    iget v0, p0, La/e/b/h/d;->a0:I

    if-ge p1, v0, :cond_0

    iput v0, p0, La/e/b/h/d;->T:I

    :cond_0
    return-void
.end method

.method public I(La/e/b/h/d$a;)V
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x0

    aput-object p1, v0, v1

    return-void
.end method

.method public J(I)V
    .locals 0

    if-gez p1, :cond_0

    const/4 p1, 0x0

    :cond_0
    iput p1, p0, La/e/b/h/d;->a0:I

    return-void
.end method

.method public K(I)V
    .locals 0

    if-gez p1, :cond_0

    const/4 p1, 0x0

    :cond_0
    iput p1, p0, La/e/b/h/d;->Z:I

    return-void
.end method

.method public L(La/e/b/h/d$a;)V
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x1

    aput-object p1, v0, v1

    return-void
.end method

.method public M(I)V
    .locals 1

    iput p1, p0, La/e/b/h/d;->S:I

    iget v0, p0, La/e/b/h/d;->Z:I

    if-ge p1, v0, :cond_0

    iput v0, p0, La/e/b/h/d;->S:I

    :cond_0
    return-void
.end method

.method public N(ZZ)V
    .locals 8

    sget-object v0, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    iget-object v1, p0, La/e/b/h/d;->d:La/e/b/h/l/k;

    .line 1
    iget-boolean v2, v1, La/e/b/h/l/o;->g:Z

    and-int/2addr p1, v2

    .line 2
    iget-object v2, p0, La/e/b/h/d;->e:La/e/b/h/l/m;

    .line 3
    iget-boolean v3, v2, La/e/b/h/l/o;->g:Z

    and-int/2addr p2, v3

    .line 4
    iget-object v3, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v3, v3, La/e/b/h/l/f;->g:I

    iget-object v4, v2, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v4, v4, La/e/b/h/l/f;->g:I

    iget-object v1, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v1, v1, La/e/b/h/l/f;->g:I

    iget-object v2, v2, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v2, v2, La/e/b/h/l/f;->g:I

    sub-int v5, v1, v3

    sub-int v6, v2, v4

    const/4 v7, 0x0

    if-ltz v5, :cond_0

    if-ltz v6, :cond_0

    const/high16 v5, -0x80000000

    if-eq v3, v5, :cond_0

    const v6, 0x7fffffff

    if-eq v3, v6, :cond_0

    if-eq v4, v5, :cond_0

    if-eq v4, v6, :cond_0

    if-eq v1, v5, :cond_0

    if-eq v1, v6, :cond_0

    if-eq v2, v5, :cond_0

    if-ne v2, v6, :cond_1

    :cond_0
    move v1, v7

    move v2, v1

    move v3, v2

    move v4, v3

    :cond_1
    sub-int/2addr v1, v3

    sub-int/2addr v2, v4

    if-eqz p1, :cond_2

    iput v3, p0, La/e/b/h/d;->W:I

    :cond_2
    if-eqz p2, :cond_3

    iput v4, p0, La/e/b/h/d;->X:I

    :cond_3
    iget v3, p0, La/e/b/h/d;->e0:I

    const/16 v4, 0x8

    if-ne v3, v4, :cond_4

    iput v7, p0, La/e/b/h/d;->S:I

    iput v7, p0, La/e/b/h/d;->T:I

    return-void

    :cond_4
    if-eqz p1, :cond_6

    iget-object p1, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object p1, p1, v7

    if-ne p1, v0, :cond_5

    iget p1, p0, La/e/b/h/d;->S:I

    if-ge v1, p1, :cond_5

    move v1, p1

    :cond_5
    iput v1, p0, La/e/b/h/d;->S:I

    iget p1, p0, La/e/b/h/d;->Z:I

    if-ge v1, p1, :cond_6

    iput p1, p0, La/e/b/h/d;->S:I

    :cond_6
    if-eqz p2, :cond_8

    iget-object p1, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 p2, 0x1

    aget-object p1, p1, p2

    if-ne p1, v0, :cond_7

    iget p1, p0, La/e/b/h/d;->T:I

    if-ge v2, p1, :cond_7

    move v2, p1

    :cond_7
    iput v2, p0, La/e/b/h/d;->T:I

    iget p1, p0, La/e/b/h/d;->a0:I

    if-ge v2, p1, :cond_8

    iput p1, p0, La/e/b/h/d;->T:I

    :cond_8
    return-void
.end method

.method public O(La/e/b/d;Z)V
    .locals 6

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->o(Ljava/lang/Object;)I

    move-result v0

    iget-object v1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {p1, v1}, La/e/b/d;->o(Ljava/lang/Object;)I

    move-result v1

    iget-object v2, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p1, v2}, La/e/b/d;->o(Ljava/lang/Object;)I

    move-result v2

    iget-object v3, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p1, v3}, La/e/b/d;->o(Ljava/lang/Object;)I

    move-result p1

    if-eqz p2, :cond_0

    iget-object v3, p0, La/e/b/h/d;->d:La/e/b/h/l/k;

    if-eqz v3, :cond_0

    iget-object v4, v3, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v5, v4, La/e/b/h/l/f;->j:Z

    if-eqz v5, :cond_0

    iget-object v3, v3, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v5, v3, La/e/b/h/l/f;->j:Z

    if-eqz v5, :cond_0

    iget v0, v4, La/e/b/h/l/f;->g:I

    iget v2, v3, La/e/b/h/l/f;->g:I

    :cond_0
    if-eqz p2, :cond_1

    iget-object p2, p0, La/e/b/h/d;->e:La/e/b/h/l/m;

    if-eqz p2, :cond_1

    iget-object v3, p2, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v4, v3, La/e/b/h/l/f;->j:Z

    if-eqz v4, :cond_1

    iget-object p2, p2, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v4, p2, La/e/b/h/l/f;->j:Z

    if-eqz v4, :cond_1

    iget v1, v3, La/e/b/h/l/f;->g:I

    iget p1, p2, La/e/b/h/l/f;->g:I

    :cond_1
    sub-int p2, v2, v0

    sub-int v3, p1, v1

    const/4 v4, 0x0

    if-ltz p2, :cond_2

    if-ltz v3, :cond_2

    const/high16 p2, -0x80000000

    if-eq v0, p2, :cond_2

    const v3, 0x7fffffff

    if-eq v0, v3, :cond_2

    if-eq v1, p2, :cond_2

    if-eq v1, v3, :cond_2

    if-eq v2, p2, :cond_2

    if-eq v2, v3, :cond_2

    if-eq p1, p2, :cond_2

    if-ne p1, v3, :cond_3

    :cond_2
    move p1, v4

    move v0, p1

    move v1, v0

    move v2, v1

    .line 1
    :cond_3
    sget-object p2, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sub-int/2addr v2, v0

    sub-int/2addr p1, v1

    iput v0, p0, La/e/b/h/d;->W:I

    iput v1, p0, La/e/b/h/d;->X:I

    iget v0, p0, La/e/b/h/d;->e0:I

    const/16 v1, 0x8

    if-ne v0, v1, :cond_4

    iput v4, p0, La/e/b/h/d;->S:I

    iput v4, p0, La/e/b/h/d;->T:I

    goto :goto_0

    :cond_4
    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v0, v0, v4

    if-ne v0, p2, :cond_5

    iget v0, p0, La/e/b/h/d;->S:I

    if-ge v2, v0, :cond_5

    move v2, v0

    :cond_5
    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    if-ne v0, p2, :cond_6

    iget p2, p0, La/e/b/h/d;->T:I

    if-ge p1, p2, :cond_6

    move p1, p2

    :cond_6
    iput v2, p0, La/e/b/h/d;->S:I

    iput p1, p0, La/e/b/h/d;->T:I

    iget p2, p0, La/e/b/h/d;->a0:I

    if-ge p1, p2, :cond_7

    iput p2, p0, La/e/b/h/d;->T:I

    :cond_7
    iget p1, p0, La/e/b/h/d;->S:I

    iget p2, p0, La/e/b/h/d;->Z:I

    if-ge p1, p2, :cond_8

    iput p2, p0, La/e/b/h/d;->S:I

    :cond_8
    :goto_0
    return-void
.end method

.method public b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/e/b/h/e;",
            "La/e/b/d;",
            "Ljava/util/HashSet<",
            "La/e/b/h/d;",
            ">;IZ)V"
        }
    .end annotation

    if-eqz p5, :cond_1

    invoke-virtual {p3, p0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p5

    if-nez p5, :cond_0

    return-void

    :cond_0
    invoke-static {p1, p2, p0}, La/e/b/h/i;->a(La/e/b/h/e;La/e/b/d;La/e/b/h/d;)V

    invoke-virtual {p3, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    const/16 p5, 0x40

    invoke-virtual {p1, p5}, La/e/b/h/e;->Y(I)Z

    move-result p5

    invoke-virtual {p0, p2, p5}, La/e/b/h/d;->d(La/e/b/d;Z)V

    :cond_1
    if-nez p4, :cond_3

    iget-object p5, p0, La/e/b/h/d;->F:La/e/b/h/c;

    .line 1
    iget-object p5, p5, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz p5, :cond_2

    .line 2
    invoke-virtual {p5}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p5

    :goto_0
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v6, 0x1

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v1 .. v6}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    goto :goto_0

    :cond_2
    iget-object p5, p0, La/e/b/h/d;->H:La/e/b/h/c;

    .line 3
    iget-object p5, p5, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz p5, :cond_6

    .line 4
    invoke-virtual {p5}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p5

    :goto_1
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-interface {p5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v6, 0x1

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v1 .. v6}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    goto :goto_1

    :cond_3
    iget-object p5, p0, La/e/b/h/d;->G:La/e/b/h/c;

    .line 5
    iget-object p5, p5, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz p5, :cond_4

    .line 6
    invoke-virtual {p5}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p5

    :goto_2
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v6, 0x1

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v1 .. v6}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    goto :goto_2

    :cond_4
    iget-object p5, p0, La/e/b/h/d;->I:La/e/b/h/c;

    .line 7
    iget-object p5, p5, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz p5, :cond_5

    .line 8
    invoke-virtual {p5}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p5

    :goto_3
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {p5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v6, 0x1

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v1 .. v6}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    goto :goto_3

    :cond_5
    iget-object p5, p0, La/e/b/h/d;->J:La/e/b/h/c;

    .line 9
    iget-object p5, p5, La/e/b/h/c;->a:Ljava/util/HashSet;

    if-eqz p5, :cond_6

    .line 10
    invoke-virtual {p5}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p5

    :goto_4
    invoke-interface {p5}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-interface {p5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    const/4 v6, 0x1

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-virtual/range {v1 .. v6}, La/e/b/h/d;->b(La/e/b/h/e;La/e/b/d;Ljava/util/HashSet;IZ)V

    goto :goto_4

    :cond_6
    return-void
.end method

.method public c()Z
    .locals 1

    instance-of v0, p0, La/e/b/h/j;

    if-nez v0, :cond_1

    instance-of v0, p0, La/e/b/h/f;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    return v0
.end method

.method public d(La/e/b/d;Z)V
    .locals 53

    move-object/from16 v15, p0

    move-object/from16 v14, p1

    sget-object v13, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    sget-object v12, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    iget-object v0, v15, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v11

    iget-object v0, v15, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v10

    iget-object v0, v15, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v9

    iget-object v0, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v8

    iget-object v0, v15, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v7

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    const/4 v6, 0x1

    const/4 v5, 0x0

    if-eqz v0, :cond_2

    if-eqz v0, :cond_0

    iget-object v0, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v0, v0, v5

    if-ne v0, v13, :cond_0

    move v0, v6

    goto :goto_0

    :cond_0
    move v0, v5

    :goto_0
    iget-object v1, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_1

    iget-object v1, v1, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v1, v1, v6

    if-ne v1, v13, :cond_1

    move v1, v6

    goto :goto_1

    :cond_1
    move v1, v5

    :goto_1
    move/from16 v29, v0

    move/from16 v28, v1

    goto :goto_2

    :cond_2
    move/from16 v28, v5

    move/from16 v29, v28

    :goto_2
    iget v0, v15, La/e/b/h/d;->e0:I

    const/16 v4, 0x8

    if-ne v0, v4, :cond_5

    .line 1
    iget-object v0, v15, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    move v1, v5

    :goto_3
    if-ge v1, v0, :cond_4

    iget-object v2, v15, La/e/b/h/d;->O:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->f()Z

    move-result v2

    if-eqz v2, :cond_3

    move v0, v6

    goto :goto_4

    :cond_3
    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    :cond_4
    move v0, v5

    :goto_4
    if-nez v0, :cond_5

    .line 2
    iget-object v0, v15, La/e/b/h/d;->P:[Z

    aget-boolean v1, v0, v5

    if-nez v1, :cond_5

    aget-boolean v0, v0, v6

    if-nez v0, :cond_5

    return-void

    :cond_5
    iget-boolean v0, v15, La/e/b/h/d;->j:Z

    const/4 v3, 0x5

    if-nez v0, :cond_6

    iget-boolean v0, v15, La/e/b/h/d;->k:Z

    if-eqz v0, :cond_c

    :cond_6
    iget-boolean v0, v15, La/e/b/h/d;->j:Z

    if-eqz v0, :cond_8

    iget v0, v15, La/e/b/h/d;->W:I

    invoke-virtual {v14, v11, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget v0, v15, La/e/b/h/d;->W:I

    iget v1, v15, La/e/b/h/d;->S:I

    add-int/2addr v0, v1

    invoke-virtual {v14, v10, v0}, La/e/b/d;->e(La/e/b/g;I)V

    if-eqz v29, :cond_8

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_8

    iget-boolean v1, v15, La/e/b/h/d;->i:Z

    if-eqz v1, :cond_7

    check-cast v0, La/e/b/h/e;

    iget-object v1, v15, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0, v1}, La/e/b/h/e;->U(La/e/b/h/c;)V

    iget-object v1, v15, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0, v1}, La/e/b/h/e;->S(La/e/b/h/c;)V

    goto :goto_5

    :cond_7
    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {v14, v0, v10, v5, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_8
    :goto_5
    iget-boolean v0, v15, La/e/b/h/d;->k:Z

    if-eqz v0, :cond_b

    iget v0, v15, La/e/b/h/d;->X:I

    invoke-virtual {v14, v9, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget v0, v15, La/e/b/h/d;->X:I

    iget v1, v15, La/e/b/h/d;->T:I

    add-int/2addr v0, v1

    invoke-virtual {v14, v8, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->f()Z

    move-result v0

    if-eqz v0, :cond_9

    iget v0, v15, La/e/b/h/d;->X:I

    iget v1, v15, La/e/b/h/d;->Y:I

    add-int/2addr v0, v1

    invoke-virtual {v14, v7, v0}, La/e/b/d;->e(La/e/b/g;I)V

    :cond_9
    if-eqz v28, :cond_b

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_b

    iget-boolean v1, v15, La/e/b/h/d;->i:Z

    if-eqz v1, :cond_a

    check-cast v0, La/e/b/h/e;

    iget-object v1, v15, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0, v1}, La/e/b/h/e;->U(La/e/b/h/c;)V

    iget-object v1, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0, v1}, La/e/b/h/e;->T(La/e/b/h/c;)V

    goto :goto_6

    :cond_a
    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {v14, v0, v8, v5, v3}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_b
    :goto_6
    iget-boolean v0, v15, La/e/b/h/d;->j:Z

    if-eqz v0, :cond_c

    iget-boolean v0, v15, La/e/b/h/d;->k:Z

    if-eqz v0, :cond_c

    iput-boolean v5, v15, La/e/b/h/d;->j:Z

    iput-boolean v5, v15, La/e/b/h/d;->k:Z

    return-void

    :cond_c
    if-eqz p2, :cond_f

    iget-object v0, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    if-eqz v0, :cond_f

    iget-object v1, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    if-eqz v1, :cond_f

    iget-object v2, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v3, v2, La/e/b/h/l/f;->j:Z

    if-eqz v3, :cond_f

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_f

    iget-object v0, v1, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_f

    iget-object v0, v1, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_f

    iget v0, v2, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v11, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v10, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v9, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v8, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v7, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_e

    if-eqz v29, :cond_d

    iget-object v0, v15, La/e/b/h/d;->f:[Z

    aget-boolean v0, v0, v5

    if-eqz v0, :cond_d

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->w()Z

    move-result v0

    if-nez v0, :cond_d

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {v14, v0, v10, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_d
    if-eqz v28, :cond_e

    iget-object v0, v15, La/e/b/h/d;->f:[Z

    aget-boolean v0, v0, v6

    if-eqz v0, :cond_e

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->x()Z

    move-result v0

    if-nez v0, :cond_e

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {v14, v0, v8, v5, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_e
    iput-boolean v5, v15, La/e/b/h/d;->j:Z

    iput-boolean v5, v15, La/e/b/h/d;->k:Z

    return-void

    :cond_f
    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_14

    invoke-virtual {v15, v5}, La/e/b/h/d;->v(I)Z

    move-result v0

    if-eqz v0, :cond_10

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    check-cast v0, La/e/b/h/e;

    invoke-virtual {v0, v15, v5}, La/e/b/h/e;->Q(La/e/b/h/d;I)V

    move v0, v6

    goto :goto_7

    :cond_10
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->w()Z

    move-result v0

    :goto_7
    invoke-virtual {v15, v6}, La/e/b/h/d;->v(I)Z

    move-result v1

    if-eqz v1, :cond_11

    iget-object v1, v15, La/e/b/h/d;->R:La/e/b/h/d;

    check-cast v1, La/e/b/h/e;

    invoke-virtual {v1, v15, v6}, La/e/b/h/e;->Q(La/e/b/h/d;I)V

    move v1, v6

    goto :goto_8

    :cond_11
    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->x()Z

    move-result v1

    :goto_8
    if-nez v0, :cond_12

    if-eqz v29, :cond_12

    iget v2, v15, La/e/b/h/d;->e0:I

    if-eq v2, v4, :cond_12

    iget-object v2, v15, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_12

    iget-object v2, v15, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_12

    iget-object v2, v15, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    invoke-virtual {v14, v2, v10, v5, v6}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_12
    if-nez v1, :cond_13

    if-eqz v28, :cond_13

    iget v2, v15, La/e/b/h/d;->e0:I

    if-eq v2, v4, :cond_13

    iget-object v2, v15, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_13

    iget-object v2, v15, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_13

    iget-object v2, v15, La/e/b/h/d;->J:La/e/b/h/c;

    if-nez v2, :cond_13

    iget-object v2, v15, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v2, v2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    invoke-virtual {v14, v2, v8, v5, v6}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_13
    move/from16 v31, v0

    move/from16 v30, v1

    goto :goto_9

    :cond_14
    move/from16 v30, v5

    move/from16 v31, v30

    :goto_9
    iget v0, v15, La/e/b/h/d;->S:I

    iget v1, v15, La/e/b/h/d;->Z:I

    if-ge v0, v1, :cond_15

    move v0, v1

    :cond_15
    iget v1, v15, La/e/b/h/d;->T:I

    iget v2, v15, La/e/b/h/d;->a0:I

    if-ge v1, v2, :cond_16

    move v1, v2

    :cond_16
    iget-object v2, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v2, v2, v5

    if-eq v2, v12, :cond_17

    move v2, v6

    goto :goto_a

    :cond_17
    move v2, v5

    :goto_a
    iget-object v3, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v3, v3, v6

    if-eq v3, v12, :cond_18

    move v3, v6

    goto :goto_b

    :cond_18
    move v3, v5

    :goto_b
    iget v6, v15, La/e/b/h/d;->V:I

    iput v6, v15, La/e/b/h/d;->w:I

    iget v6, v15, La/e/b/h/d;->U:F

    iput v6, v15, La/e/b/h/d;->x:F

    iget v5, v15, La/e/b/h/d;->n:I

    iget v4, v15, La/e/b/h/d;->o:I

    const/16 v20, 0x0

    cmpl-float v6, v6, v20

    const/16 v20, 0x4

    move/from16 v21, v0

    if-lez v6, :cond_2b

    iget v6, v15, La/e/b/h/d;->e0:I

    const/16 v0, 0x8

    if-eq v6, v0, :cond_2b

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v6, 0x0

    aget-object v0, v0, v6

    if-ne v0, v12, :cond_19

    if-nez v5, :cond_19

    const/4 v5, 0x3

    :cond_19
    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/16 v17, 0x1

    aget-object v0, v0, v17

    if-ne v0, v12, :cond_1a

    if-nez v4, :cond_1a

    const/4 v4, 0x3

    :cond_1a
    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/16 v18, 0x0

    aget-object v6, v0, v18

    const/high16 v24, 0x3f800000    # 1.0f

    if-ne v6, v12, :cond_25

    aget-object v0, v0, v17

    if-ne v0, v12, :cond_25

    const/4 v0, 0x3

    if-ne v5, v0, :cond_25

    if-ne v4, v0, :cond_25

    .line 3
    iget v0, v15, La/e/b/h/d;->w:I

    const/4 v6, -0x1

    if-ne v0, v6, :cond_1c

    if-eqz v2, :cond_1b

    if-nez v3, :cond_1b

    const/4 v0, 0x0

    iput v0, v15, La/e/b/h/d;->w:I

    goto :goto_c

    :cond_1b
    if-nez v2, :cond_1c

    if-eqz v3, :cond_1c

    const/4 v0, 0x1

    iput v0, v15, La/e/b/h/d;->w:I

    iget v0, v15, La/e/b/h/d;->V:I

    if-ne v0, v6, :cond_1c

    iget v0, v15, La/e/b/h/d;->x:F

    div-float v0, v24, v0

    iput v0, v15, La/e/b/h/d;->x:F

    :cond_1c
    :goto_c
    iget v0, v15, La/e/b/h/d;->w:I

    if-nez v0, :cond_1e

    iget-object v0, v15, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_1d

    iget-object v0, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-nez v0, :cond_1e

    :cond_1d
    const/4 v0, 0x1

    :goto_d
    iput v0, v15, La/e/b/h/d;->w:I

    goto :goto_e

    :cond_1e
    const/4 v0, 0x1

    iget v2, v15, La/e/b/h/d;->w:I

    if-ne v2, v0, :cond_20

    iget-object v0, v15, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_1f

    iget-object v0, v15, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-nez v0, :cond_20

    :cond_1f
    const/4 v0, 0x0

    goto :goto_d

    :cond_20
    :goto_e
    iget v0, v15, La/e/b/h/d;->w:I

    const/4 v2, -0x1

    if-ne v0, v2, :cond_23

    iget-object v0, v15, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_21

    iget-object v0, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_21

    iget-object v0, v15, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_21

    iget-object v0, v15, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-nez v0, :cond_23

    :cond_21
    iget-object v0, v15, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_22

    iget-object v0, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_22

    const/4 v0, 0x0

    :goto_f
    iput v0, v15, La/e/b/h/d;->w:I

    goto :goto_10

    :cond_22
    iget-object v0, v15, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_23

    iget-object v0, v15, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_23

    iget v0, v15, La/e/b/h/d;->x:F

    div-float v0, v24, v0

    iput v0, v15, La/e/b/h/d;->x:F

    const/4 v0, 0x1

    goto :goto_f

    :cond_23
    :goto_10
    iget v0, v15, La/e/b/h/d;->w:I

    const/4 v2, -0x1

    if-ne v0, v2, :cond_29

    iget v0, v15, La/e/b/h/d;->q:I

    if-lez v0, :cond_24

    iget v0, v15, La/e/b/h/d;->t:I

    if-nez v0, :cond_24

    const/4 v0, 0x0

    :goto_11
    iput v0, v15, La/e/b/h/d;->w:I

    goto/16 :goto_12

    :cond_24
    iget v0, v15, La/e/b/h/d;->q:I

    if-nez v0, :cond_29

    iget v0, v15, La/e/b/h/d;->t:I

    if-lez v0, :cond_29

    iget v0, v15, La/e/b/h/d;->x:F

    div-float v0, v24, v0

    iput v0, v15, La/e/b/h/d;->x:F

    const/4 v0, 0x1

    goto :goto_11

    .line 4
    :cond_25
    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v2, 0x0

    aget-object v3, v0, v2

    if-ne v3, v12, :cond_27

    const/4 v3, 0x3

    if-ne v5, v3, :cond_27

    iput v2, v15, La/e/b/h/d;->w:I

    iget v2, v15, La/e/b/h/d;->x:F

    iget v3, v15, La/e/b/h/d;->T:I

    int-to-float v3, v3

    mul-float/2addr v2, v3

    float-to-int v2, v2

    const/4 v3, 0x1

    aget-object v0, v0, v3

    move/from16 v32, v1

    if-eq v0, v12, :cond_26

    move v0, v2

    move/from16 v34, v4

    move/from16 v35, v20

    const/16 v18, 0x0

    const/16 v33, 0x0

    goto :goto_14

    :cond_26
    move v0, v2

    move/from16 v33, v3

    move/from16 v34, v4

    move/from16 v35, v5

    const/16 v18, 0x0

    goto :goto_14

    :cond_27
    const/4 v3, 0x1

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v0, v0, v3

    if-ne v0, v12, :cond_29

    const/4 v0, 0x3

    if-ne v4, v0, :cond_29

    iput v3, v15, La/e/b/h/d;->w:I

    iget v0, v15, La/e/b/h/d;->V:I

    const/4 v1, -0x1

    if-ne v0, v1, :cond_28

    iget v0, v15, La/e/b/h/d;->x:F

    div-float v0, v24, v0

    iput v0, v15, La/e/b/h/d;->x:F

    :cond_28
    iget v0, v15, La/e/b/h/d;->x:F

    iget v1, v15, La/e/b/h/d;->S:I

    int-to-float v1, v1

    mul-float/2addr v0, v1

    float-to-int v1, v0

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/16 v18, 0x0

    aget-object v0, v0, v18

    if-eq v0, v12, :cond_2a

    move/from16 v32, v1

    move/from16 v35, v5

    move/from16 v33, v18

    move/from16 v34, v20

    goto :goto_13

    :cond_29
    :goto_12
    const/16 v18, 0x0

    :cond_2a
    move/from16 v32, v1

    move/from16 v34, v4

    move/from16 v35, v5

    move/from16 v0, v21

    const/16 v33, 0x1

    goto :goto_14

    :cond_2b
    const/16 v18, 0x0

    move/from16 v32, v1

    move/from16 v34, v4

    move/from16 v35, v5

    move/from16 v33, v18

    :goto_13
    move/from16 v0, v21

    :goto_14
    iget-object v1, v15, La/e/b/h/d;->p:[I

    aput v35, v1, v18

    const/4 v2, 0x1

    aput v34, v1, v2

    if-eqz v33, :cond_2d

    iget v1, v15, La/e/b/h/d;->w:I

    const/4 v2, -0x1

    if-eqz v1, :cond_2c

    if-ne v1, v2, :cond_2e

    :cond_2c
    const/16 v20, 0x1

    goto :goto_15

    :cond_2d
    const/4 v2, -0x1

    :cond_2e
    const/16 v20, 0x0

    :goto_15
    if-eqz v33, :cond_30

    iget v1, v15, La/e/b/h/d;->w:I

    const/4 v3, 0x1

    if-eq v1, v3, :cond_2f

    if-ne v1, v2, :cond_30

    :cond_2f
    const/16 v36, 0x1

    goto :goto_16

    :cond_30
    const/16 v36, 0x0

    :goto_16
    iget-object v1, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    if-ne v1, v13, :cond_31

    instance-of v1, v15, La/e/b/h/e;

    if-eqz v1, :cond_31

    const/16 v21, 0x1

    goto :goto_17

    :cond_31
    const/16 v21, 0x0

    :goto_17
    if-eqz v21, :cond_32

    const/16 v22, 0x0

    goto :goto_18

    :cond_32
    move/from16 v22, v0

    :goto_18
    iget-object v0, v15, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    const/4 v1, 0x1

    xor-int/lit8 v37, v0, 0x1

    iget-object v0, v15, La/e/b/h/d;->P:[Z

    const/4 v2, 0x0

    aget-boolean v23, v0, v2

    aget-boolean v38, v0, v1

    iget v0, v15, La/e/b/h/d;->l:I

    const/4 v6, 0x2

    const/16 v39, 0x0

    if-eq v0, v6, :cond_38

    iget-boolean v0, v15, La/e/b/h/d;->j:Z

    if-nez v0, :cond_38

    if-eqz p2, :cond_34

    iget-object v0, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    if-eqz v0, :cond_34

    iget-object v1, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v2, v1, La/e/b/h/l/f;->j:Z

    if-eqz v2, :cond_34

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-nez v0, :cond_33

    goto :goto_19

    :cond_33
    if-eqz p2, :cond_38

    iget v0, v1, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v11, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->d:La/e/b/h/l/k;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    invoke-virtual {v14, v10, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_38

    if-eqz v29, :cond_38

    iget-object v0, v15, La/e/b/h/d;->f:[Z

    const/4 v1, 0x0

    aget-boolean v0, v0, v1

    if-eqz v0, :cond_38

    invoke-virtual/range {p0 .. p0}, La/e/b/h/d;->w()Z

    move-result v0

    if-nez v0, :cond_38

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    const/16 v4, 0x8

    invoke-virtual {v14, v0, v10, v1, v4}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto/16 :goto_1d

    :cond_34
    :goto_19
    const/16 v4, 0x8

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_35

    iget-object v0, v0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    move-object/from16 v19, v0

    goto :goto_1a

    :cond_35
    move-object/from16 v19, v39

    :goto_1a
    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_36

    iget-object v0, v0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    move-object/from16 v27, v0

    goto :goto_1b

    :cond_36
    move-object/from16 v27, v39

    :goto_1b
    iget-object v0, v15, La/e/b/h/d;->f:[Z

    const/4 v5, 0x0

    aget-boolean v18, v0, v5

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v40, v0, v5

    iget-object v3, v15, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v1, v15, La/e/b/h/d;->H:La/e/b/h/c;

    iget v2, v15, La/e/b/h/d;->W:I

    move/from16 v42, v2

    iget v2, v15, La/e/b/h/d;->Z:I

    iget-object v4, v15, La/e/b/h/d;->y:[I

    aget v44, v4, v5

    iget v4, v15, La/e/b/h/d;->b0:F

    const/16 v17, 0x1

    aget-object v0, v0, v17

    if-ne v0, v12, :cond_37

    move/from16 v45, v17

    goto :goto_1c

    :cond_37
    move/from16 v45, v5

    :goto_1c
    iget v0, v15, La/e/b/h/d;->q:I

    move/from16 v24, v0

    iget v0, v15, La/e/b/h/d;->r:I

    move/from16 v25, v0

    iget v0, v15, La/e/b/h/d;->s:F

    move/from16 v26, v0

    move-object/from16 v0, p0

    move-object/from16 v46, v1

    move-object/from16 v1, p1

    move/from16 v41, v42

    move/from16 v42, v2

    const/4 v2, 0x1

    move-object/from16 v16, v3

    move/from16 v3, v29

    move/from16 v43, v4

    move/from16 v4, v28

    move/from16 v5, v18

    move-object/from16 v6, v27

    move-object/from16 v47, v7

    move-object/from16 v7, v19

    move-object/from16 v48, v8

    move-object/from16 v8, v40

    move-object/from16 v49, v9

    move/from16 v9, v21

    move-object/from16 v40, v10

    move-object/from16 v10, v16

    move-object/from16 v50, v11

    move-object/from16 v11, v46

    move-object/from16 v51, v12

    move/from16 v12, v41

    move-object/from16 v52, v13

    move/from16 v13, v22

    move/from16 v14, v42

    move/from16 v15, v44

    move/from16 v16, v43

    move/from16 v17, v20

    move/from16 v18, v45

    move/from16 v19, v31

    move/from16 v20, v30

    move/from16 v21, v23

    move/from16 v22, v35

    move/from16 v23, v34

    move/from16 v27, v37

    invoke-virtual/range {v0 .. v27}, La/e/b/h/d;->f(La/e/b/d;ZZZZLa/e/b/g;La/e/b/g;La/e/b/h/d$a;ZLa/e/b/h/c;La/e/b/h/c;IIIIFZZZZZIIIIFZ)V

    goto :goto_1e

    :cond_38
    :goto_1d
    move-object/from16 v47, v7

    move-object/from16 v48, v8

    move-object/from16 v49, v9

    move-object/from16 v40, v10

    move-object/from16 v50, v11

    move-object/from16 v51, v12

    move-object/from16 v52, v13

    :goto_1e
    if-eqz p2, :cond_3c

    move-object/from16 v15, p0

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    if-eqz v0, :cond_3b

    iget-object v1, v0, La/e/b/h/l/o;->h:La/e/b/h/l/f;

    iget-boolean v2, v1, La/e/b/h/l/f;->j:Z

    if-eqz v2, :cond_3b

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget-boolean v0, v0, La/e/b/h/l/f;->j:Z

    if-eqz v0, :cond_3b

    iget v0, v1, La/e/b/h/l/f;->g:I

    move-object/from16 v14, p1

    move-object/from16 v13, v49

    invoke-virtual {v14, v13, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/o;->i:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    move-object/from16 v12, v48

    invoke-virtual {v14, v12, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->e:La/e/b/h/l/m;

    iget-object v0, v0, La/e/b/h/l/m;->k:La/e/b/h/l/f;

    iget v0, v0, La/e/b/h/l/f;->g:I

    move-object/from16 v1, v47

    invoke-virtual {v14, v1, v0}, La/e/b/d;->e(La/e/b/g;I)V

    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_3a

    if-nez v30, :cond_3a

    if-eqz v28, :cond_3a

    iget-object v2, v15, La/e/b/h/d;->f:[Z

    const/4 v11, 0x1

    aget-boolean v2, v2, v11

    if-eqz v2, :cond_39

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    const/16 v2, 0x8

    const/4 v10, 0x0

    invoke-virtual {v14, v0, v12, v10, v2}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_1f

    :cond_39
    const/16 v2, 0x8

    const/4 v10, 0x0

    goto :goto_1f

    :cond_3a
    const/16 v2, 0x8

    const/4 v10, 0x0

    const/4 v11, 0x1

    :goto_1f
    move v6, v10

    goto :goto_21

    :cond_3b
    move-object/from16 v14, p1

    move-object/from16 v1, v47

    move-object/from16 v12, v48

    move-object/from16 v13, v49

    const/16 v2, 0x8

    const/4 v10, 0x0

    const/4 v11, 0x1

    goto :goto_20

    :cond_3c
    const/16 v2, 0x8

    const/4 v10, 0x0

    const/4 v11, 0x1

    move-object/from16 v15, p0

    move-object/from16 v14, p1

    move-object/from16 v1, v47

    move-object/from16 v12, v48

    move-object/from16 v13, v49

    :goto_20
    move v6, v11

    :goto_21
    iget v0, v15, La/e/b/h/d;->m:I

    const/4 v3, 0x2

    if-ne v0, v3, :cond_3d

    move v5, v10

    goto :goto_22

    :cond_3d
    move v5, v6

    :goto_22
    if-eqz v5, :cond_48

    iget-boolean v0, v15, La/e/b/h/d;->k:Z

    if-nez v0, :cond_48

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v0, v0, v11

    move-object/from16 v3, v52

    if-ne v0, v3, :cond_3e

    instance-of v0, v15, La/e/b/h/e;

    if-eqz v0, :cond_3e

    move v9, v11

    goto :goto_23

    :cond_3e
    move v9, v10

    :goto_23
    if-eqz v9, :cond_3f

    move/from16 v32, v10

    :cond_3f
    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_40

    iget-object v0, v0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    move-object v7, v0

    goto :goto_24

    :cond_40
    move-object/from16 v7, v39

    :goto_24
    iget-object v0, v15, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_41

    iget-object v0, v0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    move-object v6, v0

    goto :goto_25

    :cond_41
    move-object/from16 v6, v39

    :goto_25
    iget v0, v15, La/e/b/h/d;->Y:I

    if-gtz v0, :cond_42

    iget v0, v15, La/e/b/h/d;->e0:I

    if-ne v0, v2, :cond_46

    :cond_42
    iget-object v0, v15, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_44

    .line 5
    iget v0, v15, La/e/b/h/d;->Y:I

    .line 6
    invoke-virtual {v14, v1, v13, v0, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    iget-object v0, v15, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    invoke-virtual {v14, v1, v0, v10, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    if-eqz v28, :cond_43

    iget-object v0, v15, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {v14, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v0

    const/4 v1, 0x5

    invoke-virtual {v14, v7, v0, v10, v1}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_43
    move/from16 v27, v10

    goto :goto_27

    :cond_44
    iget v0, v15, La/e/b/h/d;->e0:I

    if-ne v0, v2, :cond_45

    invoke-virtual {v14, v1, v13, v10, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_26

    .line 7
    :cond_45
    iget v0, v15, La/e/b/h/d;->Y:I

    .line 8
    invoke-virtual {v14, v1, v13, v0, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    :cond_46
    :goto_26
    move/from16 v27, v37

    :goto_27
    iget-object v0, v15, La/e/b/h/d;->f:[Z

    aget-boolean v5, v0, v11

    iget-object v0, v15, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v8, v0, v11

    iget-object v4, v15, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v3, v15, La/e/b/h/d;->I:La/e/b/h/c;

    iget v1, v15, La/e/b/h/d;->X:I

    iget v2, v15, La/e/b/h/d;->a0:I

    iget-object v10, v15, La/e/b/h/d;->y:[I

    aget v16, v10, v11

    iget v10, v15, La/e/b/h/d;->c0:F

    const/16 v17, 0x0

    aget-object v0, v0, v17

    move-object/from16 v11, v51

    if-ne v0, v11, :cond_47

    const/16 v18, 0x1

    goto :goto_28

    :cond_47
    move/from16 v18, v17

    :goto_28
    iget v0, v15, La/e/b/h/d;->t:I

    move/from16 v24, v0

    iget v0, v15, La/e/b/h/d;->u:I

    move/from16 v25, v0

    iget v0, v15, La/e/b/h/d;->v:F

    move/from16 v26, v0

    move-object/from16 v0, p0

    move/from16 v19, v1

    move-object/from16 v1, p1

    move/from16 v20, v2

    const/4 v2, 0x0

    move-object v11, v3

    move/from16 v3, v28

    move-object/from16 v21, v4

    move/from16 v4, v29

    move/from16 v17, v10

    move-object/from16 v10, v21

    move-object/from16 v28, v12

    move/from16 v12, v19

    move-object/from16 v29, v13

    move/from16 v13, v32

    move/from16 v14, v20

    move/from16 v15, v16

    move/from16 v16, v17

    move/from16 v17, v36

    move/from16 v19, v30

    move/from16 v20, v31

    move/from16 v21, v38

    move/from16 v22, v34

    move/from16 v23, v35

    invoke-virtual/range {v0 .. v27}, La/e/b/h/d;->f(La/e/b/d;ZZZZLa/e/b/g;La/e/b/g;La/e/b/h/d$a;ZLa/e/b/h/c;La/e/b/h/c;IIIIFZZZZZIIIIFZ)V

    goto :goto_29

    :cond_48
    move-object/from16 v28, v12

    move-object/from16 v29, v13

    :goto_29
    if-eqz v33, :cond_4a

    const/16 v6, 0x8

    move-object/from16 v7, p0

    iget v0, v7, La/e/b/h/d;->w:I

    const/4 v1, 0x1

    iget v5, v7, La/e/b/h/d;->x:F

    if-ne v0, v1, :cond_49

    move-object/from16 v0, p1

    move-object/from16 v1, v28

    move-object/from16 v2, v29

    move-object/from16 v3, v40

    move-object/from16 v4, v50

    goto :goto_2a

    :cond_49
    const/16 v6, 0x8

    move-object/from16 v0, p1

    move-object/from16 v1, v40

    move-object/from16 v2, v50

    move-object/from16 v3, v28

    move-object/from16 v4, v29

    :goto_2a
    invoke-virtual/range {v0 .. v6}, La/e/b/d;->h(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;FI)V

    goto :goto_2b

    :cond_4a
    move-object/from16 v7, p0

    :goto_2b
    iget-object v0, v7, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v0}, La/e/b/h/c;->g()Z

    move-result v0

    if-eqz v0, :cond_4b

    iget-object v0, v7, La/e/b/h/d;->M:La/e/b/h/c;

    .line 9
    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    .line 10
    iget-object v0, v0, La/e/b/h/c;->d:La/e/b/h/d;

    .line 11
    iget v1, v7, La/e/b/h/d;->z:F

    const/high16 v2, 0x42b40000    # 90.0f

    add-float/2addr v1, v2

    float-to-double v1, v1

    invoke-static {v1, v2}, Ljava/lang/Math;->toRadians(D)D

    move-result-wide v1

    double-to-float v1, v1

    iget-object v2, v7, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    .line 12
    sget-object v3, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    sget-object v4, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    sget-object v5, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    sget-object v6, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-virtual {v7, v6}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    move-object/from16 v9, p1

    invoke-virtual {v9, v8}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v11

    invoke-virtual {v7, v5}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    invoke-virtual {v9, v8}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v13

    invoke-virtual {v7, v4}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v8

    invoke-virtual {v9, v8}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v8

    invoke-virtual {v7, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v10

    invoke-virtual {v9, v10}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v14

    invoke-virtual {v0, v6}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v6

    invoke-virtual {v9, v6}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v6

    invoke-virtual {v0, v5}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v5

    invoke-virtual {v9, v5}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v15

    invoke-virtual {v0, v4}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v4

    invoke-virtual {v9, v4}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v4

    invoke-virtual {v0, v3}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v0

    invoke-virtual {v9, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v16

    invoke-virtual/range {p1 .. p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    move-object/from16 p2, v4

    float-to-double v3, v1

    invoke-static {v3, v4}, Ljava/lang/Math;->sin(D)D

    move-result-wide v17

    int-to-double v1, v2

    move-object/from16 v19, v6

    mul-double v5, v17, v1

    double-to-float v5, v5

    move-object v12, v0

    move/from16 v17, v5

    invoke-virtual/range {v12 .. v17}, La/e/b/b;->g(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;F)La/e/b/b;

    invoke-virtual {v9, v0}, La/e/b/d;->c(La/e/b/b;)V

    invoke-virtual/range {p1 .. p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v0

    invoke-static {v3, v4}, Ljava/lang/Math;->cos(D)D

    move-result-wide v3

    mul-double/2addr v3, v1

    double-to-float v15, v3

    move-object v10, v0

    move-object v12, v8

    move-object/from16 v13, v19

    move-object/from16 v14, p2

    invoke-virtual/range {v10 .. v15}, La/e/b/b;->g(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;F)La/e/b/b;

    invoke-virtual {v9, v0}, La/e/b/d;->c(La/e/b/b;)V

    :cond_4b
    const/4 v0, 0x0

    .line 13
    iput-boolean v0, v7, La/e/b/h/d;->j:Z

    iput-boolean v0, v7, La/e/b/h/d;->k:Z

    return-void
.end method

.method public e()Z
    .locals 2

    iget v0, p0, La/e/b/h/d;->e0:I

    const/16 v1, 0x8

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public final f(La/e/b/d;ZZZZLa/e/b/g;La/e/b/g;La/e/b/h/d$a;ZLa/e/b/h/c;La/e/b/h/c;IIIIFZZZZZIIIIFZ)V
    .locals 30

    move-object/from16 v0, p0

    move-object/from16 v10, p1

    move-object/from16 v11, p6

    move-object/from16 v12, p7

    move-object/from16 v13, p10

    move-object/from16 v14, p11

    move/from16 v15, p14

    move/from16 v1, p15

    move/from16 v2, p23

    move/from16 v3, p24

    move/from16 v4, p25

    sget-object v5, La/e/b/h/c$a;->f:La/e/b/h/c$a;

    sget-object v6, La/e/b/h/c$a;->d:La/e/b/h/c$a;

    invoke-virtual {v10, v13}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v9

    invoke-virtual {v10, v14}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v8

    .line 1
    iget-object v7, v13, La/e/b/h/c;->f:La/e/b/h/c;

    .line 2
    invoke-virtual {v10, v7}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v7

    .line 3
    iget-object v12, v14, La/e/b/h/c;->f:La/e/b/h/c;

    .line 4
    invoke-virtual {v10, v12}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v12

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->g()Z

    move-result v22

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->g()Z

    move-result v23

    iget-object v2, v0, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {v2}, La/e/b/h/c;->g()Z

    move-result v2

    if-eqz v23, :cond_0

    add-int/lit8 v16, v22, 0x1

    goto :goto_0

    :cond_0
    move/from16 v16, v22

    :goto_0
    if-eqz v2, :cond_1

    add-int/lit8 v16, v16, 0x1

    :cond_1
    move/from16 v14, v16

    if-eqz p17, :cond_2

    move-object/from16 v25, v12

    const/4 v11, 0x3

    goto :goto_1

    :cond_2
    move/from16 v11, p22

    move-object/from16 v25, v12

    :goto_1
    invoke-virtual/range {p8 .. p8}, Ljava/lang/Enum;->ordinal()I

    move-result v12

    move-object/from16 v16, v5

    const/4 v5, 0x1

    if-eqz v12, :cond_4

    if-eq v12, v5, :cond_4

    const/4 v5, 0x2

    if-eq v12, v5, :cond_3

    goto :goto_2

    :cond_3
    const/4 v5, 0x4

    if-eq v11, v5, :cond_5

    const/4 v12, 0x1

    goto :goto_3

    :cond_4
    :goto_2
    const/4 v5, 0x4

    :cond_5
    const/4 v12, 0x0

    :goto_3
    iget v5, v0, La/e/b/h/d;->e0:I

    move/from16 v17, v12

    const/16 v12, 0x8

    if-ne v5, v12, :cond_6

    const/4 v5, 0x0

    const/16 v17, 0x0

    goto :goto_4

    :cond_6
    move/from16 v5, p13

    :goto_4
    if-eqz p27, :cond_9

    if-nez v22, :cond_7

    if-nez v23, :cond_7

    if-nez v2, :cond_7

    move/from16 v12, p12

    invoke-virtual {v10, v9, v12}, La/e/b/d;->e(La/e/b/g;I)V

    goto :goto_5

    :cond_7
    if-eqz v22, :cond_8

    if-nez v23, :cond_8

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v12

    move/from16 v28, v2

    const/16 v2, 0x8

    invoke-virtual {v10, v9, v7, v12, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_6

    :cond_8
    :goto_5
    move/from16 v28, v2

    const/16 v2, 0x8

    goto :goto_6

    :cond_9
    move/from16 v28, v2

    move v2, v12

    :goto_6
    if-nez v17, :cond_d

    const/4 v6, 0x3

    if-eqz p9, :cond_b

    const/4 v12, 0x0

    invoke-virtual {v10, v8, v9, v12, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    if-lez v15, :cond_a

    invoke-virtual {v10, v8, v9, v15, v2}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_a
    const v5, 0x7fffffff

    if-ge v1, v5, :cond_c

    invoke-virtual {v10, v8, v9, v1, v2}, La/e/b/d;->g(La/e/b/g;La/e/b/g;II)V

    goto :goto_7

    :cond_b
    invoke-virtual {v10, v8, v9, v5, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    :cond_c
    :goto_7
    move/from16 v2, p5

    move v1, v6

    goto/16 :goto_f

    :cond_d
    const/4 v1, 0x3

    const/4 v2, 0x2

    if-eq v14, v2, :cond_10

    if-nez p17, :cond_10

    const/4 v2, 0x1

    if-eq v11, v2, :cond_e

    if-nez v11, :cond_10

    :cond_e
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    move-result v2

    if-lez v4, :cond_f

    invoke-static {v4, v2}, Ljava/lang/Math;->min(II)I

    move-result v2

    :cond_f
    const/16 v5, 0x8

    invoke-virtual {v10, v8, v9, v2, v5}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto/16 :goto_e

    :cond_10
    const/4 v2, -0x2

    if-ne v3, v2, :cond_11

    move v3, v5

    :cond_11
    if-ne v4, v2, :cond_12

    move v4, v5

    :cond_12
    if-lez v5, :cond_13

    const/4 v2, 0x1

    if-eq v11, v2, :cond_13

    const/4 v5, 0x0

    :cond_13
    if-lez v3, :cond_14

    const/16 v2, 0x8

    invoke-virtual {v10, v8, v9, v3, v2}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    move-result v5

    :cond_14
    if-lez v4, :cond_17

    if-eqz p3, :cond_15

    const/4 v2, 0x1

    if-ne v11, v2, :cond_15

    const/4 v2, 0x0

    goto :goto_8

    :cond_15
    const/4 v2, 0x1

    :goto_8
    if-eqz v2, :cond_16

    const/16 v2, 0x8

    invoke-virtual {v10, v8, v9, v4, v2}, La/e/b/d;->g(La/e/b/g;La/e/b/g;II)V

    goto :goto_9

    :cond_16
    const/16 v2, 0x8

    :goto_9
    invoke-static {v5, v4}, Ljava/lang/Math;->min(II)I

    move-result v5

    goto :goto_a

    :cond_17
    const/16 v2, 0x8

    :goto_a
    const/4 v12, 0x1

    if-ne v11, v12, :cond_19

    if-eqz p3, :cond_18

    invoke-virtual {v10, v8, v9, v5, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_b

    :cond_18
    const/4 v6, 0x5

    invoke-virtual {v10, v8, v9, v5, v6}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    invoke-virtual {v10, v8, v9, v5, v2}, La/e/b/d;->g(La/e/b/g;La/e/b/g;II)V

    :goto_b
    move/from16 v2, p5

    goto :goto_f

    :cond_19
    const/4 v2, 0x2

    if-ne v11, v2, :cond_1c

    .line 5
    iget-object v2, v13, La/e/b/h/c;->e:La/e/b/h/c$a;

    move-object/from16 v5, v16

    if-eq v2, v6, :cond_1b

    if-ne v2, v5, :cond_1a

    goto :goto_c

    .line 6
    :cond_1a
    iget-object v2, v0, La/e/b/h/d;->R:La/e/b/h/d;

    sget-object v5, La/e/b/h/c$a;->c:La/e/b/h/c$a;

    invoke-virtual {v2, v5}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    invoke-virtual {v10, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    iget-object v5, v0, La/e/b/h/d;->R:La/e/b/h/d;

    sget-object v6, La/e/b/h/c$a;->e:La/e/b/h/c$a;

    invoke-virtual {v5, v6}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v5

    goto :goto_d

    :cond_1b
    :goto_c
    iget-object v2, v0, La/e/b/h/d;->R:La/e/b/h/d;

    invoke-virtual {v2, v6}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v2

    invoke-virtual {v10, v2}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v2

    iget-object v6, v0, La/e/b/h/d;->R:La/e/b/h/d;

    invoke-virtual {v6, v5}, La/e/b/h/d;->i(La/e/b/h/c$a;)La/e/b/h/c;

    move-result-object v5

    :goto_d
    invoke-virtual {v10, v5}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    move-result-object v5

    move-object/from16 v20, v2

    move-object/from16 v19, v5

    invoke-virtual/range {p1 .. p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v2

    move-object/from16 v16, v2

    move-object/from16 v17, v8

    move-object/from16 v18, v9

    move/from16 v21, p26

    invoke-virtual/range {v16 .. v21}, La/e/b/b;->d(La/e/b/g;La/e/b/g;La/e/b/g;La/e/b/g;F)La/e/b/b;

    invoke-virtual {v10, v2}, La/e/b/d;->c(La/e/b/b;)V

    :goto_e
    move/from16 v12, p5

    move/from16 v16, v3

    const/16 v17, 0x0

    goto :goto_10

    :cond_1c
    const/4 v2, 0x1

    :goto_f
    move v12, v2

    move/from16 v16, v3

    :goto_10
    if-eqz p27, :cond_58

    if-eqz p19, :cond_1d

    move-object/from16 v2, p6

    move-object/from16 v4, p7

    move-object v3, v8

    move-object v13, v9

    move/from16 p9, v12

    move v5, v14

    const/4 v1, 0x0

    const/4 v6, 0x2

    const/16 v26, 0x1

    goto/16 :goto_31

    :cond_1d
    if-nez v22, :cond_1e

    if-nez v23, :cond_1e

    if-nez v28, :cond_1e

    goto :goto_11

    :cond_1e
    if-eqz v22, :cond_1f

    if-nez v23, :cond_1f

    :goto_11
    move-object v3, v8

    move/from16 p9, v12

    move-object/from16 v14, v25

    :goto_12
    const/4 v1, 0x0

    goto/16 :goto_2d

    :cond_1f
    if-nez v22, :cond_24

    if-eqz v23, :cond_24

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v1

    neg-int v1, v1

    move-object/from16 v14, v25

    const/16 v2, 0x8

    invoke-virtual {v10, v8, v14, v1, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    if-eqz p3, :cond_23

    iget-boolean v1, v0, La/e/b/h/d;->h:Z

    if-eqz v1, :cond_22

    iget-boolean v1, v9, La/e/b/g;->g:Z

    if-eqz v1, :cond_22

    iget-object v1, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_22

    check-cast v1, La/e/b/h/e;

    if-eqz p2, :cond_21

    .line 7
    iget-object v2, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    if-eqz v2, :cond_20

    invoke-virtual {v2}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_20

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->c()I

    move-result v2

    iget-object v3, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v3}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/c;

    invoke-virtual {v3}, La/e/b/h/c;->c()I

    move-result v3

    if-le v2, v3, :cond_23

    :cond_20
    new-instance v2, Ljava/lang/ref/WeakReference;

    invoke-direct {v2, v13}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, La/e/b/h/e;->E0:Ljava/lang/ref/WeakReference;

    goto :goto_13

    .line 8
    :cond_21
    invoke-virtual {v1, v13}, La/e/b/h/e;->U(La/e/b/h/c;)V

    goto :goto_13

    :cond_22
    move-object/from16 v6, p6

    const/4 v1, 0x5

    const/4 v5, 0x0

    invoke-virtual {v10, v9, v6, v5, v1}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto/16 :goto_2c

    :cond_23
    :goto_13
    move-object v3, v8

    move/from16 p9, v12

    goto :goto_12

    :cond_24
    move-object/from16 v6, p6

    move v3, v1

    move-object/from16 v14, v25

    const/4 v5, 0x0

    if-eqz v22, :cond_53

    if-eqz v23, :cond_53

    iget-object v1, v13, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v2, v1, La/e/b/h/c;->d:La/e/b/h/d;

    move-object/from16 v1, p11

    iget-object v5, v1, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v5, v5, La/e/b/h/c;->d:La/e/b/h/d;

    .line 9
    iget-object v3, v0, La/e/b/h/d;->R:La/e/b/h/d;

    const/16 v18, 0x6

    if-eqz v17, :cond_37

    if-nez v11, :cond_29

    if-nez v4, :cond_26

    if-nez v16, :cond_26

    .line 10
    iget-boolean v4, v7, La/e/b/g;->g:Z

    if-eqz v4, :cond_25

    iget-boolean v4, v14, La/e/b/g;->g:Z

    if-eqz v4, :cond_25

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v2

    const/16 v3, 0x8

    invoke-virtual {v10, v9, v7, v2, v3}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v1

    neg-int v1, v1

    invoke-virtual {v10, v8, v14, v1, v3}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    return-void

    :cond_25
    const/16 p5, 0x0

    const/16 v19, 0x1

    const/16 v20, 0x0

    const/16 v21, 0x8

    const/16 v22, 0x8

    goto :goto_14

    :cond_26
    const/16 p5, 0x1

    const/16 v19, 0x0

    const/16 v20, 0x1

    const/16 v21, 0x5

    const/16 v22, 0x5

    :goto_14
    instance-of v4, v2, La/e/b/h/a;

    if-nez v4, :cond_27

    instance-of v4, v5, La/e/b/h/a;

    if-eqz v4, :cond_28

    :cond_27
    const/16 v22, 0x4

    :cond_28
    move/from16 v4, p5

    move/from16 v27, v20

    move/from16 v23, v21

    const/4 v13, 0x1

    move/from16 v20, v18

    move/from16 v21, v19

    move/from16 v19, v11

    goto :goto_17

    :cond_29
    const/4 v13, 0x1

    if-ne v11, v13, :cond_2a

    move/from16 v19, v11

    move/from16 v11, v18

    const/4 v4, 0x4

    const/4 v13, 0x0

    goto :goto_16

    :cond_2a
    const/4 v13, 0x3

    if-ne v11, v13, :cond_36

    iget v13, v0, La/e/b/h/d;->w:I

    move/from16 v19, v11

    const/4 v11, -0x1

    if-ne v13, v11, :cond_2d

    if-eqz p20, :cond_2c

    if-eqz p3, :cond_2b

    const/4 v4, 0x5

    goto :goto_15

    :cond_2b
    const/4 v4, 0x4

    goto :goto_15

    :cond_2c
    const/16 v4, 0x8

    :goto_15
    move v11, v4

    const/4 v4, 0x5

    const/4 v13, 0x1

    :goto_16
    move/from16 v22, v4

    move/from16 v20, v11

    move/from16 v21, v13

    const/4 v4, 0x1

    const/4 v13, 0x1

    const/16 v23, 0x8

    const/16 v27, 0x1

    :goto_17
    move-object/from16 v11, p7

    goto/16 :goto_20

    :cond_2d
    if-eqz p17, :cond_31

    move/from16 v11, p23

    const/4 v13, 0x2

    if-eq v11, v13, :cond_2f

    const/4 v13, 0x1

    if-ne v11, v13, :cond_2e

    goto :goto_18

    :cond_2e
    const/4 v4, 0x0

    goto :goto_19

    :cond_2f
    const/4 v13, 0x1

    :goto_18
    move v4, v13

    :goto_19
    if-nez v4, :cond_30

    const/4 v4, 0x5

    const/16 v11, 0x8

    goto :goto_1a

    :cond_30
    const/4 v4, 0x4

    const/4 v11, 0x5

    :goto_1a
    move/from16 v22, v4

    move/from16 v23, v11

    move v4, v13

    move/from16 v21, v4

    move/from16 v27, v21

    move/from16 v20, v18

    goto :goto_17

    :cond_31
    const/4 v13, 0x1

    if-lez v4, :cond_32

    move-object/from16 v11, p7

    move v4, v13

    move/from16 v20, v4

    move/from16 v21, v20

    const/16 v22, 0x5

    goto/16 :goto_1f

    :cond_32
    if-nez v4, :cond_35

    if-nez v16, :cond_35

    if-nez p20, :cond_33

    move-object/from16 v11, p7

    move v4, v13

    move/from16 v20, v4

    move/from16 v21, v20

    const/16 v22, 0x8

    goto/16 :goto_1f

    :cond_33
    if-eq v2, v3, :cond_34

    if-eq v5, v3, :cond_34

    const/4 v4, 0x4

    goto :goto_1b

    :cond_34
    const/4 v4, 0x5

    :goto_1b
    move-object/from16 v11, p7

    move/from16 v23, v4

    move v4, v13

    move/from16 v21, v4

    move/from16 v27, v21

    move/from16 v20, v18

    const/16 v22, 0x4

    goto/16 :goto_20

    :cond_35
    move-object/from16 v11, p7

    move v4, v13

    move/from16 v20, v4

    move/from16 v21, v20

    goto :goto_1e

    :cond_36
    move/from16 v19, v11

    const/4 v13, 0x1

    move-object/from16 v11, p7

    const/4 v4, 0x0

    const/16 v20, 0x0

    goto :goto_1d

    :cond_37
    move/from16 v19, v11

    const/4 v13, 0x1

    iget-boolean v4, v7, La/e/b/g;->g:Z

    if-eqz v4, :cond_3a

    iget-boolean v4, v14, La/e/b/g;->g:Z

    if-eqz v4, :cond_3a

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v2

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v3

    const/16 v4, 0x8

    move-object/from16 p17, p1

    move-object/from16 p18, v9

    move-object/from16 p19, v7

    move/from16 p20, v2

    move/from16 p21, p16

    move-object/from16 p22, v14

    move-object/from16 p23, v8

    move/from16 p24, v3

    move/from16 p25, v4

    invoke-virtual/range {p17 .. p25}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    if-eqz p3, :cond_39

    if-eqz v12, :cond_39

    iget-object v2, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v2, :cond_38

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v5

    move-object/from16 v11, p7

    goto :goto_1c

    :cond_38
    move-object/from16 v11, p7

    const/4 v5, 0x0

    :goto_1c
    if-eq v14, v11, :cond_39

    const/4 v1, 0x5

    invoke-virtual {v10, v11, v8, v5, v1}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_39
    return-void

    :cond_3a
    move-object/from16 v11, p7

    move v4, v13

    move/from16 v20, v4

    :goto_1d
    const/16 v21, 0x0

    :goto_1e
    const/16 v22, 0x4

    :goto_1f
    move/from16 v27, v20

    const/16 v23, 0x5

    move/from16 v20, v18

    :goto_20
    if-eqz v27, :cond_3b

    if-ne v7, v14, :cond_3b

    if-eq v2, v3, :cond_3b

    const/16 v25, 0x0

    const/16 v27, 0x0

    goto :goto_21

    :cond_3b
    move/from16 v25, v13

    :goto_21
    if-eqz v4, :cond_3d

    if-nez v17, :cond_3c

    if-nez p18, :cond_3c

    if-nez p20, :cond_3c

    if-ne v7, v6, :cond_3c

    if-ne v14, v11, :cond_3c

    const/16 v20, 0x0

    const/16 v23, 0x8

    const/16 v25, 0x0

    const/16 v28, 0x8

    goto :goto_22

    :cond_3c
    move/from16 v28, v23

    move/from16 v23, v20

    move/from16 v20, p3

    :goto_22
    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v4

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v29

    move-object v13, v1

    move-object/from16 v1, p1

    move-object v11, v2

    move-object v2, v9

    move-object v13, v3

    move/from16 p9, v12

    const/4 v12, 0x3

    move-object v3, v7

    move-object v12, v5

    const/16 v24, 0x4

    const/16 v26, 0x1

    move/from16 v5, p16

    move-object v15, v6

    move-object v6, v14

    move-object v15, v7

    move-object v7, v8

    move-object/from16 p8, v13

    move-object v13, v8

    move/from16 v8, v29

    move-object/from16 v29, v13

    move-object v13, v9

    move/from16 v9, v23

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    move/from16 v5, v25

    move/from16 v23, v28

    goto :goto_23

    :cond_3d
    move-object v11, v2

    move-object/from16 p8, v3

    move-object v15, v7

    move-object/from16 v29, v8

    move/from16 p9, v12

    move/from16 v26, v13

    const/16 v24, 0x4

    move-object v12, v5

    move-object v13, v9

    move/from16 v20, p3

    move/from16 v5, v25

    :goto_23
    iget v1, v0, La/e/b/h/d;->e0:I

    const/16 v2, 0x8

    if-ne v1, v2, :cond_3e

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->f()Z

    move-result v1

    if-nez v1, :cond_3e

    return-void

    :cond_3e
    if-eqz v27, :cond_41

    if-eqz v20, :cond_40

    if-eq v15, v14, :cond_40

    if-nez v17, :cond_40

    instance-of v1, v11, La/e/b/h/a;

    if-nez v1, :cond_3f

    instance-of v1, v12, La/e/b/h/a;

    if-eqz v1, :cond_40

    :cond_3f
    move/from16 v1, v18

    goto :goto_24

    :cond_40
    move/from16 v1, v23

    :goto_24
    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v2

    invoke-virtual {v10, v13, v15, v2, v1}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    move-object/from16 v3, v29

    invoke-virtual {v10, v3, v14, v2, v1}, La/e/b/d;->g(La/e/b/g;La/e/b/g;II)V

    move/from16 v23, v1

    goto :goto_25

    :cond_41
    move-object/from16 v3, v29

    :goto_25
    if-eqz v20, :cond_42

    if-eqz p21, :cond_42

    instance-of v1, v11, La/e/b/h/a;

    if-nez v1, :cond_42

    instance-of v1, v12, La/e/b/h/a;

    if-nez v1, :cond_42

    move/from16 v1, v18

    move v2, v1

    move/from16 v5, v26

    goto :goto_26

    :cond_42
    move/from16 v1, v22

    move/from16 v2, v23

    :goto_26
    if-eqz v5, :cond_4e

    if-eqz v21, :cond_4b

    if-eqz p20, :cond_43

    if-eqz p4, :cond_4b

    :cond_43
    move-object/from16 v4, p8

    if-eq v11, v4, :cond_45

    if-ne v12, v4, :cond_44

    goto :goto_27

    :cond_44
    move/from16 v18, v1

    :cond_45
    :goto_27
    instance-of v5, v11, La/e/b/h/f;

    if-nez v5, :cond_46

    instance-of v5, v12, La/e/b/h/f;

    if-eqz v5, :cond_47

    :cond_46
    const/16 v18, 0x5

    :cond_47
    instance-of v5, v11, La/e/b/h/a;

    if-nez v5, :cond_48

    instance-of v5, v12, La/e/b/h/a;

    if-eqz v5, :cond_49

    :cond_48
    const/16 v18, 0x5

    :cond_49
    if-eqz p20, :cond_4a

    const/4 v5, 0x5

    goto :goto_28

    :cond_4a
    move/from16 v5, v18

    :goto_28
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    move-result v1

    goto :goto_29

    :cond_4b
    move-object/from16 v4, p8

    :goto_29
    move v5, v1

    if-eqz v20, :cond_4d

    invoke-static {v2, v5}, Ljava/lang/Math;->min(II)I

    move-result v5

    if-eqz p17, :cond_4d

    if-nez p20, :cond_4d

    if-eq v11, v4, :cond_4c

    if-ne v12, v4, :cond_4d

    :cond_4c
    move/from16 v5, v24

    :cond_4d
    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v1

    invoke-virtual {v10, v13, v15, v1, v5}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v1

    neg-int v1, v1

    invoke-virtual {v10, v3, v14, v1, v5}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    :cond_4e
    if-eqz v20, :cond_50

    move-object/from16 v1, p6

    move-object v2, v15

    if-ne v1, v2, :cond_4f

    invoke-virtual/range {p10 .. p10}, La/e/b/h/c;->d()I

    move-result v5

    goto :goto_2a

    :cond_4f
    const/4 v5, 0x0

    :goto_2a
    if-eq v2, v1, :cond_50

    const/4 v2, 0x5

    invoke-virtual {v10, v13, v1, v5, v2}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_50
    if-eqz v20, :cond_52

    if-eqz v17, :cond_52

    if-nez p14, :cond_52

    if-nez v16, :cond_52

    if-eqz v17, :cond_51

    move/from16 v11, v19

    const/4 v1, 0x3

    if-ne v11, v1, :cond_51

    const/4 v1, 0x0

    const/16 v12, 0x8

    goto :goto_2b

    :cond_51
    const/4 v1, 0x0

    const/4 v12, 0x5

    :goto_2b
    invoke-virtual {v10, v3, v13, v1, v12}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_2e

    :cond_52
    const/4 v1, 0x0

    goto :goto_2e

    :cond_53
    :goto_2c
    move v1, v5

    move-object v3, v8

    move/from16 p9, v12

    :goto_2d
    move/from16 v20, p3

    :goto_2e
    if-eqz v20, :cond_57

    if-eqz p9, :cond_57

    move-object/from16 v2, p11

    iget-object v4, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_54

    invoke-virtual/range {p11 .. p11}, La/e/b/h/c;->d()I

    move-result v5

    move-object/from16 v4, p7

    goto :goto_2f

    :cond_54
    move-object/from16 v4, p7

    move v5, v1

    :goto_2f
    if-eq v14, v4, :cond_57

    iget-boolean v1, v0, La/e/b/h/d;->h:Z

    if-eqz v1, :cond_56

    iget-boolean v1, v3, La/e/b/g;->g:Z

    if-eqz v1, :cond_56

    iget-object v1, v0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v1, :cond_56

    check-cast v1, La/e/b/h/e;

    if-eqz p2, :cond_55

    invoke-virtual {v1, v2}, La/e/b/h/e;->S(La/e/b/h/c;)V

    goto :goto_30

    :cond_55
    invoke-virtual {v1, v2}, La/e/b/h/e;->T(La/e/b/h/c;)V

    :goto_30
    return-void

    :cond_56
    const/4 v1, 0x5

    invoke-virtual {v10, v4, v3, v5, v1}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_57
    return-void

    :cond_58
    move-object/from16 v2, p6

    move-object/from16 v4, p7

    move-object v3, v8

    move-object v13, v9

    move/from16 p9, v12

    move v5, v14

    const/4 v1, 0x0

    const/16 v26, 0x1

    const/4 v6, 0x2

    :goto_31
    if-ge v5, v6, :cond_5d

    if-eqz p3, :cond_5d

    if-eqz p9, :cond_5d

    const/16 v5, 0x8

    invoke-virtual {v10, v13, v2, v1, v5}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    if-nez p2, :cond_5a

    iget-object v2, v0, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-nez v2, :cond_59

    goto :goto_32

    :cond_59
    move v5, v1

    goto :goto_33

    :cond_5a
    :goto_32
    move/from16 v5, v26

    :goto_33
    if-nez p2, :cond_5c

    iget-object v2, v0, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v2, :cond_5c

    iget-object v2, v2, La/e/b/h/c;->d:La/e/b/h/d;

    iget v5, v2, La/e/b/h/d;->U:F

    const/4 v6, 0x0

    cmpl-float v5, v5, v6

    if-eqz v5, :cond_5b

    iget-object v2, v2, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v5, v2, v1

    sget-object v6, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    if-ne v5, v6, :cond_5b

    aget-object v2, v2, v26

    if-ne v2, v6, :cond_5b

    move/from16 v5, v26

    goto :goto_34

    :cond_5b
    move v5, v1

    :cond_5c
    :goto_34
    if-eqz v5, :cond_5d

    const/16 v2, 0x8

    invoke-virtual {v10, v4, v3, v1, v2}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_5d
    return-void
.end method

.method public g(La/e/b/d;)V
    .locals 1

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    iget v0, p0, La/e/b/h/d;->Y:I

    if-lez v0, :cond_0

    iget-object v0, p0, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {p1, v0}, La/e/b/d;->l(Ljava/lang/Object;)La/e/b/g;

    :cond_0
    return-void
.end method

.method public h()V
    .locals 1

    iget-object v0, p0, La/e/b/h/d;->d:La/e/b/h/l/k;

    if-nez v0, :cond_0

    new-instance v0, La/e/b/h/l/k;

    invoke-direct {v0, p0}, La/e/b/h/l/k;-><init>(La/e/b/h/d;)V

    iput-object v0, p0, La/e/b/h/d;->d:La/e/b/h/l/k;

    :cond_0
    iget-object v0, p0, La/e/b/h/d;->e:La/e/b/h/l/m;

    if-nez v0, :cond_1

    new-instance v0, La/e/b/h/l/m;

    invoke-direct {v0, p0}, La/e/b/h/l/m;-><init>(La/e/b/h/d;)V

    iput-object v0, p0, La/e/b/h/d;->e:La/e/b/h/l/m;

    :cond_1
    return-void
.end method

.method public i(La/e/b/h/c$a;)La/e/b/h/c;
    .locals 1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    packed-switch v0, :pswitch_data_0

    new-instance v0, Ljava/lang/AssertionError;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    :pswitch_0
    const/4 p1, 0x0

    return-object p1

    :pswitch_1
    iget-object p1, p0, La/e/b/h/d;->L:La/e/b/h/c;

    return-object p1

    :pswitch_2
    iget-object p1, p0, La/e/b/h/d;->K:La/e/b/h/c;

    return-object p1

    :pswitch_3
    iget-object p1, p0, La/e/b/h/d;->M:La/e/b/h/c;

    return-object p1

    :pswitch_4
    iget-object p1, p0, La/e/b/h/d;->J:La/e/b/h/c;

    return-object p1

    :pswitch_5
    iget-object p1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    return-object p1

    :pswitch_6
    iget-object p1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    return-object p1

    :pswitch_7
    iget-object p1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    return-object p1

    :pswitch_8
    iget-object p1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public j()I
    .locals 2

    invoke-virtual {p0}, La/e/b/h/d;->t()I

    move-result v0

    iget v1, p0, La/e/b/h/d;->T:I

    add-int/2addr v0, v1

    return v0
.end method

.method public k(I)La/e/b/h/d$a;
    .locals 1

    if-nez p1, :cond_0

    invoke-virtual {p0}, La/e/b/h/d;->m()La/e/b/h/d$a;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 v0, 0x1

    if-ne p1, v0, :cond_1

    invoke-virtual {p0}, La/e/b/h/d;->q()La/e/b/h/d$a;

    move-result-object p1

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public l()I
    .locals 2

    iget v0, p0, La/e/b/h/d;->e0:I

    const/16 v1, 0x8

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    iget v0, p0, La/e/b/h/d;->T:I

    return v0
.end method

.method public m()La/e/b/h/d$a;
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    return-object v0
.end method

.method public n(I)La/e/b/h/d;
    .locals 2

    if-nez p1, :cond_0

    iget-object p1, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v0, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_1

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, p1, :cond_1

    iget-object p1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    return-object p1

    :cond_0
    const/4 v0, 0x1

    if-ne p1, v0, :cond_1

    iget-object p1, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v0, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_1

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, p1, :cond_1

    iget-object p1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public o(I)La/e/b/h/d;
    .locals 2

    if-nez p1, :cond_0

    iget-object p1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v0, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_1

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, p1, :cond_1

    iget-object p1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    return-object p1

    :cond_0
    const/4 v0, 0x1

    if-ne p1, v0, :cond_1

    iget-object p1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v0, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_1

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, p1, :cond_1

    iget-object p1, v0, La/e/b/h/c;->d:La/e/b/h/d;

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public p()I
    .locals 2

    invoke-virtual {p0}, La/e/b/h/d;->s()I

    move-result v0

    iget v1, p0, La/e/b/h/d;->S:I

    add-int/2addr v0, v1

    return v0
.end method

.method public q()La/e/b/h/d$a;
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    return-object v0
.end method

.method public r()I
    .locals 2

    iget v0, p0, La/e/b/h/d;->e0:I

    const/16 v1, 0x8

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    iget v0, p0, La/e/b/h/d;->S:I

    return v0
.end method

.method public s()I
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_0

    instance-of v1, v0, La/e/b/h/e;

    if-eqz v1, :cond_0

    check-cast v0, La/e/b/h/e;

    iget v0, v0, La/e/b/h/e;->u0:I

    iget v1, p0, La/e/b/h/d;->W:I

    add-int/2addr v0, v1

    return v0

    :cond_0
    iget v0, p0, La/e/b/h/d;->W:I

    return v0
.end method

.method public t()I
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->R:La/e/b/h/d;

    if-eqz v0, :cond_0

    instance-of v1, v0, La/e/b/h/e;

    if-eqz v1, :cond_0

    check-cast v0, La/e/b/h/e;

    iget v0, v0, La/e/b/h/e;->v0:I

    iget v1, p0, La/e/b/h/d;->X:I

    add-int/2addr v0, v1

    return v0

    :cond_0
    iget v0, p0, La/e/b/h/d;->X:I

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, La/e/b/h/d;->g0:Ljava/lang/String;

    const-string v2, " "

    const-string v3, ""

    if-eqz v1, :cond_0

    const-string v1, "type: "

    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    iget-object v4, p0, La/e/b/h/d;->g0:Ljava/lang/String;

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_0
    move-object v1, v3

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, La/e/b/h/d;->f0:Ljava/lang/String;

    if-eqz v1, :cond_1

    const-string v1, "id: "

    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    iget-object v3, p0, La/e/b/h/d;->f0:Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    :cond_1
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/e/b/h/d;->W:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/e/b/h/d;->X:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") - ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/e/b/h/d;->S:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " x "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, La/e/b/h/d;->T:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public u(I)Z
    .locals 4

    const/4 v0, 0x2

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-nez p1, :cond_3

    iget-object p1, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object p1, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz p1, :cond_0

    move p1, v1

    goto :goto_0

    :cond_0
    move p1, v2

    :goto_0
    iget-object v3, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_1

    move v3, v1

    goto :goto_1

    :cond_1
    move v3, v2

    :goto_1
    add-int/2addr p1, v3

    if-ge p1, v0, :cond_2

    goto :goto_2

    :cond_2
    move v1, v2

    :goto_2
    return v1

    :cond_3
    iget-object p1, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object p1, p1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz p1, :cond_4

    move p1, v1

    goto :goto_3

    :cond_4
    move p1, v2

    :goto_3
    iget-object v3, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_5

    move v3, v1

    goto :goto_4

    :cond_5
    move v3, v2

    :goto_4
    add-int/2addr p1, v3

    iget-object v3, p0, La/e/b/h/d;->J:La/e/b/h/c;

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_6

    move v3, v1

    goto :goto_5

    :cond_6
    move v3, v2

    :goto_5
    add-int/2addr p1, v3

    if-ge p1, v0, :cond_7

    goto :goto_6

    :cond_7
    move v1, v2

    :goto_6
    return v1
.end method

.method public final v(I)Z
    .locals 4

    mul-int/lit8 p1, p1, 0x2

    iget-object v0, p0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v0, p1

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    const/4 v2, 0x1

    if-eqz v1, :cond_0

    aget-object v1, v0, p1

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    aget-object v3, v0, p1

    if-eq v1, v3, :cond_0

    add-int/2addr p1, v2

    aget-object v1, v0, p1

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v1, :cond_0

    aget-object v1, v0, p1

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    aget-object p1, v0, p1

    if-ne v1, p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    return v2
.end method

.method public w()Z
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v1, :cond_0

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eq v1, v0, :cond_1

    :cond_0
    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v1, :cond_2

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, v0, :cond_2

    :cond_1
    const/4 v0, 0x1

    return v0

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public x()Z
    .locals 2

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v1, :cond_0

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eq v1, v0, :cond_1

    :cond_0
    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    iget-object v1, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v1, :cond_2

    iget-object v1, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-ne v1, v0, :cond_2

    :cond_1
    const/4 v0, 0x1

    return v0

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public y()Z
    .locals 2

    iget-boolean v0, p0, La/e/b/h/d;->g:Z

    if-eqz v0, :cond_0

    iget v0, p0, La/e/b/h/d;->e0:I

    const/16 v1, 0x8

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public z()Z
    .locals 1

    iget-boolean v0, p0, La/e/b/h/d;->j:Z

    if-nez v0, :cond_1

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    .line 1
    iget-boolean v0, v0, La/e/b/h/c;->c:Z

    if-eqz v0, :cond_0

    .line 2
    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    .line 3
    iget-boolean v0, v0, La/e/b/h/c;->c:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    return v0
.end method
