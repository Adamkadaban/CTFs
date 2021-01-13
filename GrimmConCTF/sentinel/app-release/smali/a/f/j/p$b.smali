.class public La/f/j/p$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/f/j/p;->f(La/f/j/s;)La/f/j/p;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:La/f/j/s;

.field public final synthetic b:Landroid/view/View;


# direct methods
.method public constructor <init>(La/f/j/p;La/f/j/s;Landroid/view/View;)V
    .locals 0

    iput-object p2, p0, La/f/j/p$b;->a:La/f/j/s;

    iput-object p3, p0, La/f/j/p$b;->b:Landroid/view/View;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 0

    iget-object p1, p0, La/f/j/p$b;->a:La/f/j/s;

    check-cast p1, La/b/k/r$c;

    .line 1
    iget-object p1, p1, La/b/k/r$c;->a:La/b/k/r;

    iget-object p1, p1, La/b/k/r;->d:Landroidx/appcompat/widget/ActionBarContainer;

    invoke-virtual {p1}, Landroid/widget/FrameLayout;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->invalidate()V

    return-void
.end method
