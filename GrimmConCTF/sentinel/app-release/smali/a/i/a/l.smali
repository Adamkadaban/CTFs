.class public La/i/a/l;
.super Landroid/animation/AnimatorListenerAdapter;
.source ""


# instance fields
.field public final synthetic a:Landroid/view/ViewGroup;

.field public final synthetic b:Landroid/view/View;

.field public final synthetic c:Landroidx/fragment/app/Fragment;

.field public final synthetic d:La/i/a/j;


# direct methods
.method public constructor <init>(La/i/a/j;Landroid/view/ViewGroup;Landroid/view/View;Landroidx/fragment/app/Fragment;)V
    .locals 0

    iput-object p1, p0, La/i/a/l;->d:La/i/a/j;

    iput-object p2, p0, La/i/a/l;->a:Landroid/view/ViewGroup;

    iput-object p3, p0, La/i/a/l;->b:Landroid/view/View;

    iput-object p4, p0, La/i/a/l;->c:Landroidx/fragment/app/Fragment;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 6

    iget-object p1, p0, La/i/a/l;->a:Landroid/view/ViewGroup;

    iget-object v0, p0, La/i/a/l;->b:Landroid/view/View;

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->endViewTransition(Landroid/view/View;)V

    iget-object p1, p0, La/i/a/l;->c:Landroidx/fragment/app/Fragment;

    invoke-virtual {p1}, Landroidx/fragment/app/Fragment;->i()Landroid/animation/Animator;

    move-result-object p1

    iget-object v0, p0, La/i/a/l;->c:Landroidx/fragment/app/Fragment;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/fragment/app/Fragment;->D(Landroid/animation/Animator;)V

    if-eqz p1, :cond_0

    iget-object p1, p0, La/i/a/l;->a:Landroid/view/ViewGroup;

    iget-object v0, p0, La/i/a/l;->b:Landroid/view/View;

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    move-result p1

    if-gez p1, :cond_0

    iget-object v0, p0, La/i/a/l;->d:La/i/a/j;

    iget-object v1, p0, La/i/a/l;->c:Landroidx/fragment/app/Fragment;

    invoke-virtual {v1}, Landroidx/fragment/app/Fragment;->q()I

    move-result v2

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-virtual/range {v0 .. v5}, La/i/a/j;->Z(Landroidx/fragment/app/Fragment;IIIZ)V

    :cond_0
    return-void
.end method
