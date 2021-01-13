.class public La/f/j/p$a;
.super Landroid/animation/AnimatorListenerAdapter;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/f/j/p;->e(Landroid/view/View;La/f/j/q;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/f/j/q;

.field public final synthetic b:Landroid/view/View;


# direct methods
.method public constructor <init>(La/f/j/p;La/f/j/q;Landroid/view/View;)V
    .locals 0

    iput-object p2, p0, La/f/j/p$a;->a:La/f/j/q;

    iput-object p3, p0, La/f/j/p$a;->b:Landroid/view/View;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationCancel(Landroid/animation/Animator;)V
    .locals 1

    iget-object p1, p0, La/f/j/p$a;->a:La/f/j/q;

    iget-object v0, p0, La/f/j/p$a;->b:Landroid/view/View;

    invoke-interface {p1, v0}, La/f/j/q;->c(Landroid/view/View;)V

    return-void
.end method

.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    iget-object p1, p0, La/f/j/p$a;->a:La/f/j/q;

    iget-object v0, p0, La/f/j/p$a;->b:Landroid/view/View;

    invoke-interface {p1, v0}, La/f/j/q;->a(Landroid/view/View;)V

    return-void
.end method

.method public onAnimationStart(Landroid/animation/Animator;)V
    .locals 1

    iget-object p1, p0, La/f/j/p$a;->a:La/f/j/q;

    iget-object v0, p0, La/f/j/p$a;->b:Landroid/view/View;

    invoke-interface {p1, v0}, La/f/j/q;->b(Landroid/view/View;)V

    return-void
.end method
