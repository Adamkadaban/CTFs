.class public La/b/o/i/q$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/o/i/q;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:La/b/o/i/q;


# direct methods
.method public constructor <init>(La/b/o/i/q;)V
    .locals 0

    iput-object p1, p0, La/b/o/i/q$a;->b:La/b/o/i/q;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onGlobalLayout()V
    .locals 2

    iget-object v0, p0, La/b/o/i/q$a;->b:La/b/o/i/q;

    invoke-virtual {v0}, La/b/o/i/q;->a()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, La/b/o/i/q$a;->b:La/b/o/i/q;

    iget-object v1, v0, La/b/o/i/q;->j:La/b/p/m0;

    .line 1
    iget-boolean v1, v1, La/b/p/k0;->B:Z

    if-nez v1, :cond_2

    .line 2
    iget-object v0, v0, La/b/o/i/q;->o:Landroid/view/View;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/view/View;->isShown()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/b/o/i/q$a;->b:La/b/o/i/q;

    iget-object v0, v0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {v0}, La/b/p/k0;->i()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, La/b/o/i/q$a;->b:La/b/o/i/q;

    invoke-virtual {v0}, La/b/o/i/q;->dismiss()V

    :cond_2
    :goto_1
    return-void
.end method
