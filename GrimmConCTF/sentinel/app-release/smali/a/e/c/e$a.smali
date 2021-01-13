.class public La/e/c/e$a;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/e/c/e;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field public a:I

.field public final b:La/e/c/e$d;

.field public final c:La/e/c/e$c;

.field public final d:La/e/c/e$b;

.field public final e:La/e/c/e$e;

.field public f:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "La/e/c/b;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, La/e/c/e$d;

    invoke-direct {v0}, La/e/c/e$d;-><init>()V

    iput-object v0, p0, La/e/c/e$a;->b:La/e/c/e$d;

    new-instance v0, La/e/c/e$c;

    invoke-direct {v0}, La/e/c/e$c;-><init>()V

    iput-object v0, p0, La/e/c/e$a;->c:La/e/c/e$c;

    new-instance v0, La/e/c/e$b;

    invoke-direct {v0}, La/e/c/e$b;-><init>()V

    iput-object v0, p0, La/e/c/e$a;->d:La/e/c/e$b;

    new-instance v0, La/e/c/e$e;

    invoke-direct {v0}, La/e/c/e$e;-><init>()V

    iput-object v0, p0, La/e/c/e$a;->e:La/e/c/e$e;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, La/e/c/e$a;->f:Ljava/util/HashMap;

    return-void
.end method


# virtual methods
.method public a(Landroidx/constraintlayout/widget/ConstraintLayout$a;)V
    .locals 2

    iget-object v0, p0, La/e/c/e$a;->d:La/e/c/e$b;

    iget v1, v0, La/e/c/e$b;->h:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->d:I

    iget v1, v0, La/e/c/e$b;->i:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->e:I

    iget v1, v0, La/e/c/e$b;->j:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->f:I

    iget v1, v0, La/e/c/e$b;->k:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->g:I

    iget v1, v0, La/e/c/e$b;->l:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->h:I

    iget v1, v0, La/e/c/e$b;->m:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->i:I

    iget v1, v0, La/e/c/e$b;->n:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->j:I

    iget v1, v0, La/e/c/e$b;->o:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->k:I

    iget v1, v0, La/e/c/e$b;->p:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->l:I

    iget v1, v0, La/e/c/e$b;->q:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->p:I

    iget v1, v0, La/e/c/e$b;->r:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->q:I

    iget v1, v0, La/e/c/e$b;->s:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->r:I

    iget v1, v0, La/e/c/e$b;->t:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->s:I

    iget v1, v0, La/e/c/e$b;->D:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iget v1, v0, La/e/c/e$b;->E:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iget v1, v0, La/e/c/e$b;->F:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iget v1, v0, La/e/c/e$b;->G:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    iget v1, v0, La/e/c/e$b;->O:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->x:I

    iget v1, v0, La/e/c/e$b;->N:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->y:I

    iget v1, v0, La/e/c/e$b;->K:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->u:I

    iget v1, v0, La/e/c/e$b;->M:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->w:I

    iget v1, v0, La/e/c/e$b;->u:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->z:F

    iget v1, v0, La/e/c/e$b;->v:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->A:F

    iget v1, v0, La/e/c/e$b;->x:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->m:I

    iget v1, v0, La/e/c/e$b;->y:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->n:I

    iget v1, v0, La/e/c/e$b;->z:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->o:F

    iget-object v1, v0, La/e/c/e$b;->w:Ljava/lang/String;

    iput-object v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->B:Ljava/lang/String;

    iget v1, v0, La/e/c/e$b;->A:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->P:I

    iget v1, v0, La/e/c/e$b;->B:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->Q:I

    iget v1, v0, La/e/c/e$b;->P:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->E:F

    iget v1, v0, La/e/c/e$b;->Q:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->D:F

    iget v1, v0, La/e/c/e$b;->S:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->G:I

    iget v1, v0, La/e/c/e$b;->R:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->F:I

    iget-boolean v1, v0, La/e/c/e$b;->h0:Z

    iput-boolean v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->S:Z

    iget-boolean v1, v0, La/e/c/e$b;->i0:Z

    iput-boolean v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->T:Z

    iget v1, v0, La/e/c/e$b;->T:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->H:I

    iget v1, v0, La/e/c/e$b;->U:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->I:I

    iget v1, v0, La/e/c/e$b;->V:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->L:I

    iget v1, v0, La/e/c/e$b;->W:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->M:I

    iget v1, v0, La/e/c/e$b;->X:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->J:I

    iget v1, v0, La/e/c/e$b;->Y:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->K:I

    iget v1, v0, La/e/c/e$b;->Z:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->N:F

    iget v1, v0, La/e/c/e$b;->a0:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->O:F

    iget v1, v0, La/e/c/e$b;->C:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->R:I

    iget v1, v0, La/e/c/e$b;->g:F

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->c:F

    iget v1, v0, La/e/c/e$b;->e:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->a:I

    iget v1, v0, La/e/c/e$b;->f:I

    iput v1, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->b:I

    iget v1, v0, La/e/c/e$b;->c:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    iget v1, v0, La/e/c/e$b;->d:I

    iput v1, p1, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iget-object v0, v0, La/e/c/e$b;->g0:Ljava/lang/String;

    if-eqz v0, :cond_0

    iput-object v0, p1, Landroidx/constraintlayout/widget/ConstraintLayout$a;->U:Ljava/lang/String;

    :cond_0
    iget-object v0, p0, La/e/c/e$a;->d:La/e/c/e$b;

    iget v0, v0, La/e/c/e$b;->I:I

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginStart(I)V

    iget-object v0, p0, La/e/c/e$a;->d:La/e/c/e$b;

    iget v0, v0, La/e/c/e$b;->H:I

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginEnd(I)V

    invoke-virtual {p1}, Landroidx/constraintlayout/widget/ConstraintLayout$a;->a()V

    return-void
.end method

.method public final b(ILandroidx/constraintlayout/widget/ConstraintLayout$a;)V
    .locals 1

    iput p1, p0, La/e/c/e$a;->a:I

    iget-object p1, p0, La/e/c/e$a;->d:La/e/c/e$b;

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->d:I

    iput v0, p1, La/e/c/e$b;->h:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->e:I

    iput v0, p1, La/e/c/e$b;->i:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->f:I

    iput v0, p1, La/e/c/e$b;->j:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->g:I

    iput v0, p1, La/e/c/e$b;->k:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->h:I

    iput v0, p1, La/e/c/e$b;->l:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->i:I

    iput v0, p1, La/e/c/e$b;->m:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->j:I

    iput v0, p1, La/e/c/e$b;->n:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->k:I

    iput v0, p1, La/e/c/e$b;->o:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->l:I

    iput v0, p1, La/e/c/e$b;->p:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->p:I

    iput v0, p1, La/e/c/e$b;->q:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->q:I

    iput v0, p1, La/e/c/e$b;->r:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->r:I

    iput v0, p1, La/e/c/e$b;->s:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->s:I

    iput v0, p1, La/e/c/e$b;->t:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->z:F

    iput v0, p1, La/e/c/e$b;->u:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->A:F

    iput v0, p1, La/e/c/e$b;->v:F

    iget-object v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->B:Ljava/lang/String;

    iput-object v0, p1, La/e/c/e$b;->w:Ljava/lang/String;

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->m:I

    iput v0, p1, La/e/c/e$b;->x:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->n:I

    iput v0, p1, La/e/c/e$b;->y:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->o:F

    iput v0, p1, La/e/c/e$b;->z:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->P:I

    iput v0, p1, La/e/c/e$b;->A:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->Q:I

    iput v0, p1, La/e/c/e$b;->B:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->R:I

    iput v0, p1, La/e/c/e$b;->C:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->c:F

    iput v0, p1, La/e/c/e$b;->g:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->a:I

    iput v0, p1, La/e/c/e$b;->e:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->b:I

    iput v0, p1, La/e/c/e$b;->f:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    iput v0, p1, La/e/c/e$b;->c:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iput v0, p1, La/e/c/e$b;->d:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v0, p1, La/e/c/e$b;->D:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iput v0, p1, La/e/c/e$b;->E:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iput v0, p1, La/e/c/e$b;->F:I

    iget v0, p2, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    iput v0, p1, La/e/c/e$b;->G:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->E:F

    iput v0, p1, La/e/c/e$b;->P:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->D:F

    iput v0, p1, La/e/c/e$b;->Q:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->G:I

    iput v0, p1, La/e/c/e$b;->S:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->F:I

    iput v0, p1, La/e/c/e$b;->R:I

    iget-boolean v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->S:Z

    iput-boolean v0, p1, La/e/c/e$b;->h0:Z

    iget-boolean v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->T:Z

    iput-boolean v0, p1, La/e/c/e$b;->i0:Z

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->H:I

    iput v0, p1, La/e/c/e$b;->T:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->I:I

    iput v0, p1, La/e/c/e$b;->U:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->L:I

    iput v0, p1, La/e/c/e$b;->V:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->M:I

    iput v0, p1, La/e/c/e$b;->W:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->J:I

    iput v0, p1, La/e/c/e$b;->X:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->K:I

    iput v0, p1, La/e/c/e$b;->Y:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->N:F

    iput v0, p1, La/e/c/e$b;->Z:F

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->O:F

    iput v0, p1, La/e/c/e$b;->a0:F

    iget-object v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->U:Ljava/lang/String;

    iput-object v0, p1, La/e/c/e$b;->g0:Ljava/lang/String;

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->u:I

    iput v0, p1, La/e/c/e$b;->K:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->w:I

    iput v0, p1, La/e/c/e$b;->M:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->t:I

    iput v0, p1, La/e/c/e$b;->J:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->v:I

    iput v0, p1, La/e/c/e$b;->L:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->x:I

    iput v0, p1, La/e/c/e$b;->O:I

    iget v0, p2, Landroidx/constraintlayout/widget/ConstraintLayout$a;->y:I

    iput v0, p1, La/e/c/e$b;->N:I

    invoke-virtual {p2}, Landroid/view/ViewGroup$MarginLayoutParams;->getMarginEnd()I

    move-result v0

    iput v0, p1, La/e/c/e$b;->H:I

    iget-object p1, p0, La/e/c/e$a;->d:La/e/c/e$b;

    invoke-virtual {p2}, Landroid/view/ViewGroup$MarginLayoutParams;->getMarginStart()I

    move-result p2

    iput p2, p1, La/e/c/e$b;->I:I

    return-void
.end method

.method public final c(ILa/e/c/f$a;)V
    .locals 1

    invoke-virtual {p0, p1, p2}, La/e/c/e$a;->b(ILandroidx/constraintlayout/widget/ConstraintLayout$a;)V

    iget-object p1, p0, La/e/c/e$a;->b:La/e/c/e$d;

    iget v0, p2, La/e/c/f$a;->n0:F

    iput v0, p1, La/e/c/e$d;->d:F

    iget-object p1, p0, La/e/c/e$a;->e:La/e/c/e$e;

    iget v0, p2, La/e/c/f$a;->q0:F

    iput v0, p1, La/e/c/e$e;->b:F

    iget v0, p2, La/e/c/f$a;->r0:F

    iput v0, p1, La/e/c/e$e;->c:F

    iget v0, p2, La/e/c/f$a;->s0:F

    iput v0, p1, La/e/c/e$e;->d:F

    iget v0, p2, La/e/c/f$a;->t0:F

    iput v0, p1, La/e/c/e$e;->e:F

    iget v0, p2, La/e/c/f$a;->u0:F

    iput v0, p1, La/e/c/e$e;->f:F

    iget v0, p2, La/e/c/f$a;->v0:F

    iput v0, p1, La/e/c/e$e;->g:F

    iget v0, p2, La/e/c/f$a;->w0:F

    iput v0, p1, La/e/c/e$e;->h:F

    iget v0, p2, La/e/c/f$a;->x0:F

    iput v0, p1, La/e/c/e$e;->i:F

    iget v0, p2, La/e/c/f$a;->y0:F

    iput v0, p1, La/e/c/e$e;->j:F

    iget v0, p2, La/e/c/f$a;->z0:F

    iput v0, p1, La/e/c/e$e;->k:F

    iget v0, p2, La/e/c/f$a;->p0:F

    iput v0, p1, La/e/c/e$e;->m:F

    iget-boolean p2, p2, La/e/c/f$a;->o0:Z

    iput-boolean p2, p1, La/e/c/e$e;->l:Z

    return-void
.end method

.method public clone()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, La/e/c/e$a;

    invoke-direct {v0}, La/e/c/e$a;-><init>()V

    iget-object v1, v0, La/e/c/e$a;->d:La/e/c/e$b;

    iget-object v2, p0, La/e/c/e$a;->d:La/e/c/e$b;

    const/4 v3, 0x0

    if-eqz v1, :cond_4

    .line 2
    iget-boolean v4, v2, La/e/c/e$b;->a:Z

    iput-boolean v4, v1, La/e/c/e$b;->a:Z

    iget v4, v2, La/e/c/e$b;->c:I

    iput v4, v1, La/e/c/e$b;->c:I

    iget-boolean v4, v2, La/e/c/e$b;->b:Z

    iput-boolean v4, v1, La/e/c/e$b;->b:Z

    iget v4, v2, La/e/c/e$b;->d:I

    iput v4, v1, La/e/c/e$b;->d:I

    iget v4, v2, La/e/c/e$b;->e:I

    iput v4, v1, La/e/c/e$b;->e:I

    iget v4, v2, La/e/c/e$b;->f:I

    iput v4, v1, La/e/c/e$b;->f:I

    iget v4, v2, La/e/c/e$b;->g:F

    iput v4, v1, La/e/c/e$b;->g:F

    iget v4, v2, La/e/c/e$b;->h:I

    iput v4, v1, La/e/c/e$b;->h:I

    iget v4, v2, La/e/c/e$b;->i:I

    iput v4, v1, La/e/c/e$b;->i:I

    iget v4, v2, La/e/c/e$b;->j:I

    iput v4, v1, La/e/c/e$b;->j:I

    iget v4, v2, La/e/c/e$b;->k:I

    iput v4, v1, La/e/c/e$b;->k:I

    iget v4, v2, La/e/c/e$b;->l:I

    iput v4, v1, La/e/c/e$b;->l:I

    iget v4, v2, La/e/c/e$b;->m:I

    iput v4, v1, La/e/c/e$b;->m:I

    iget v4, v2, La/e/c/e$b;->n:I

    iput v4, v1, La/e/c/e$b;->n:I

    iget v4, v2, La/e/c/e$b;->o:I

    iput v4, v1, La/e/c/e$b;->o:I

    iget v4, v2, La/e/c/e$b;->p:I

    iput v4, v1, La/e/c/e$b;->p:I

    iget v4, v2, La/e/c/e$b;->q:I

    iput v4, v1, La/e/c/e$b;->q:I

    iget v4, v2, La/e/c/e$b;->r:I

    iput v4, v1, La/e/c/e$b;->r:I

    iget v4, v2, La/e/c/e$b;->s:I

    iput v4, v1, La/e/c/e$b;->s:I

    iget v4, v2, La/e/c/e$b;->t:I

    iput v4, v1, La/e/c/e$b;->t:I

    iget v4, v2, La/e/c/e$b;->u:F

    iput v4, v1, La/e/c/e$b;->u:F

    iget v4, v2, La/e/c/e$b;->v:F

    iput v4, v1, La/e/c/e$b;->v:F

    iget-object v4, v2, La/e/c/e$b;->w:Ljava/lang/String;

    iput-object v4, v1, La/e/c/e$b;->w:Ljava/lang/String;

    iget v4, v2, La/e/c/e$b;->x:I

    iput v4, v1, La/e/c/e$b;->x:I

    iget v4, v2, La/e/c/e$b;->y:I

    iput v4, v1, La/e/c/e$b;->y:I

    iget v4, v2, La/e/c/e$b;->z:F

    iput v4, v1, La/e/c/e$b;->z:F

    iget v4, v2, La/e/c/e$b;->A:I

    iput v4, v1, La/e/c/e$b;->A:I

    iget v4, v2, La/e/c/e$b;->B:I

    iput v4, v1, La/e/c/e$b;->B:I

    iget v4, v2, La/e/c/e$b;->C:I

    iput v4, v1, La/e/c/e$b;->C:I

    iget v4, v2, La/e/c/e$b;->D:I

    iput v4, v1, La/e/c/e$b;->D:I

    iget v4, v2, La/e/c/e$b;->E:I

    iput v4, v1, La/e/c/e$b;->E:I

    iget v4, v2, La/e/c/e$b;->F:I

    iput v4, v1, La/e/c/e$b;->F:I

    iget v4, v2, La/e/c/e$b;->G:I

    iput v4, v1, La/e/c/e$b;->G:I

    iget v4, v2, La/e/c/e$b;->H:I

    iput v4, v1, La/e/c/e$b;->H:I

    iget v4, v2, La/e/c/e$b;->I:I

    iput v4, v1, La/e/c/e$b;->I:I

    iget v4, v2, La/e/c/e$b;->J:I

    iput v4, v1, La/e/c/e$b;->J:I

    iget v4, v2, La/e/c/e$b;->K:I

    iput v4, v1, La/e/c/e$b;->K:I

    iget v4, v2, La/e/c/e$b;->L:I

    iput v4, v1, La/e/c/e$b;->L:I

    iget v4, v2, La/e/c/e$b;->M:I

    iput v4, v1, La/e/c/e$b;->M:I

    iget v4, v2, La/e/c/e$b;->N:I

    iput v4, v1, La/e/c/e$b;->N:I

    iget v4, v2, La/e/c/e$b;->O:I

    iput v4, v1, La/e/c/e$b;->O:I

    iget v4, v2, La/e/c/e$b;->P:F

    iput v4, v1, La/e/c/e$b;->P:F

    iget v4, v2, La/e/c/e$b;->Q:F

    iput v4, v1, La/e/c/e$b;->Q:F

    iget v4, v2, La/e/c/e$b;->R:I

    iput v4, v1, La/e/c/e$b;->R:I

    iget v4, v2, La/e/c/e$b;->S:I

    iput v4, v1, La/e/c/e$b;->S:I

    iget v4, v2, La/e/c/e$b;->T:I

    iput v4, v1, La/e/c/e$b;->T:I

    iget v4, v2, La/e/c/e$b;->U:I

    iput v4, v1, La/e/c/e$b;->U:I

    iget v4, v2, La/e/c/e$b;->V:I

    iput v4, v1, La/e/c/e$b;->V:I

    iget v4, v2, La/e/c/e$b;->W:I

    iput v4, v1, La/e/c/e$b;->W:I

    iget v4, v2, La/e/c/e$b;->X:I

    iput v4, v1, La/e/c/e$b;->X:I

    iget v4, v2, La/e/c/e$b;->Y:I

    iput v4, v1, La/e/c/e$b;->Y:I

    iget v4, v2, La/e/c/e$b;->Z:F

    iput v4, v1, La/e/c/e$b;->Z:F

    iget v4, v2, La/e/c/e$b;->a0:F

    iput v4, v1, La/e/c/e$b;->a0:F

    iget v4, v2, La/e/c/e$b;->b0:I

    iput v4, v1, La/e/c/e$b;->b0:I

    iget v4, v2, La/e/c/e$b;->c0:I

    iput v4, v1, La/e/c/e$b;->c0:I

    iget v4, v2, La/e/c/e$b;->d0:I

    iput v4, v1, La/e/c/e$b;->d0:I

    iget-object v4, v2, La/e/c/e$b;->g0:Ljava/lang/String;

    iput-object v4, v1, La/e/c/e$b;->g0:Ljava/lang/String;

    iget-object v4, v2, La/e/c/e$b;->e0:[I

    if-eqz v4, :cond_0

    array-length v5, v4

    invoke-static {v4, v5}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object v4

    iput-object v4, v1, La/e/c/e$b;->e0:[I

    goto :goto_0

    :cond_0
    iput-object v3, v1, La/e/c/e$b;->e0:[I

    :goto_0
    iget-object v4, v2, La/e/c/e$b;->f0:Ljava/lang/String;

    iput-object v4, v1, La/e/c/e$b;->f0:Ljava/lang/String;

    iget-boolean v4, v2, La/e/c/e$b;->h0:Z

    iput-boolean v4, v1, La/e/c/e$b;->h0:Z

    iget-boolean v4, v2, La/e/c/e$b;->i0:Z

    iput-boolean v4, v1, La/e/c/e$b;->i0:Z

    iget-boolean v2, v2, La/e/c/e$b;->j0:Z

    iput-boolean v2, v1, La/e/c/e$b;->j0:Z

    .line 3
    iget-object v1, v0, La/e/c/e$a;->c:La/e/c/e$c;

    iget-object v2, p0, La/e/c/e$a;->c:La/e/c/e$c;

    if-eqz v1, :cond_3

    .line 4
    iget-boolean v4, v2, La/e/c/e$c;->a:Z

    iput-boolean v4, v1, La/e/c/e$c;->a:Z

    iget v4, v2, La/e/c/e$c;->b:I

    iput v4, v1, La/e/c/e$c;->b:I

    iget-object v4, v2, La/e/c/e$c;->c:Ljava/lang/String;

    iput-object v4, v1, La/e/c/e$c;->c:Ljava/lang/String;

    iget v4, v2, La/e/c/e$c;->d:I

    iput v4, v1, La/e/c/e$c;->d:I

    iget v4, v2, La/e/c/e$c;->e:I

    iput v4, v1, La/e/c/e$c;->e:I

    iget v4, v2, La/e/c/e$c;->g:F

    iput v4, v1, La/e/c/e$c;->g:F

    iget v2, v2, La/e/c/e$c;->f:F

    iput v2, v1, La/e/c/e$c;->f:F

    .line 5
    iget-object v1, v0, La/e/c/e$a;->b:La/e/c/e$d;

    iget-object v2, p0, La/e/c/e$a;->b:La/e/c/e$d;

    if-eqz v1, :cond_2

    .line 6
    iget-boolean v4, v2, La/e/c/e$d;->a:Z

    iput-boolean v4, v1, La/e/c/e$d;->a:Z

    iget v4, v2, La/e/c/e$d;->b:I

    iput v4, v1, La/e/c/e$d;->b:I

    iget v4, v2, La/e/c/e$d;->d:F

    iput v4, v1, La/e/c/e$d;->d:F

    iget v4, v2, La/e/c/e$d;->e:F

    iput v4, v1, La/e/c/e$d;->e:F

    iget v2, v2, La/e/c/e$d;->c:I

    iput v2, v1, La/e/c/e$d;->c:I

    .line 7
    iget-object v1, v0, La/e/c/e$a;->e:La/e/c/e$e;

    iget-object v2, p0, La/e/c/e$a;->e:La/e/c/e$e;

    if-eqz v1, :cond_1

    .line 8
    iget-boolean v3, v2, La/e/c/e$e;->a:Z

    iput-boolean v3, v1, La/e/c/e$e;->a:Z

    iget v3, v2, La/e/c/e$e;->b:F

    iput v3, v1, La/e/c/e$e;->b:F

    iget v3, v2, La/e/c/e$e;->c:F

    iput v3, v1, La/e/c/e$e;->c:F

    iget v3, v2, La/e/c/e$e;->d:F

    iput v3, v1, La/e/c/e$e;->d:F

    iget v3, v2, La/e/c/e$e;->e:F

    iput v3, v1, La/e/c/e$e;->e:F

    iget v3, v2, La/e/c/e$e;->f:F

    iput v3, v1, La/e/c/e$e;->f:F

    iget v3, v2, La/e/c/e$e;->g:F

    iput v3, v1, La/e/c/e$e;->g:F

    iget v3, v2, La/e/c/e$e;->h:F

    iput v3, v1, La/e/c/e$e;->h:F

    iget v3, v2, La/e/c/e$e;->i:F

    iput v3, v1, La/e/c/e$e;->i:F

    iget v3, v2, La/e/c/e$e;->j:F

    iput v3, v1, La/e/c/e$e;->j:F

    iget v3, v2, La/e/c/e$e;->k:F

    iput v3, v1, La/e/c/e$e;->k:F

    iget-boolean v3, v2, La/e/c/e$e;->l:Z

    iput-boolean v3, v1, La/e/c/e$e;->l:Z

    iget v2, v2, La/e/c/e$e;->m:F

    iput v2, v1, La/e/c/e$e;->m:F

    .line 9
    iget v1, p0, La/e/c/e$a;->a:I

    iput v1, v0, La/e/c/e$a;->a:I

    return-object v0

    .line 10
    :cond_1
    throw v3

    .line 11
    :cond_2
    throw v3

    .line 12
    :cond_3
    throw v3

    .line 13
    :cond_4
    throw v3
.end method
