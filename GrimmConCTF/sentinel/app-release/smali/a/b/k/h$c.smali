.class public final La/b/k/h$c;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/o/i/m$a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "c"
.end annotation


# instance fields
.field public final synthetic b:La/b/k/h;


# direct methods
.method public constructor <init>(La/b/k/h;)V
    .locals 0

    iput-object p1, p0, La/b/k/h$c;->b:La/b/k/h;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public b(La/b/o/i/g;Z)V
    .locals 0

    iget-object p2, p0, La/b/k/h$c;->b:La/b/k/h;

    invoke-virtual {p2, p1}, La/b/k/h;->t(La/b/o/i/g;)V

    return-void
.end method

.method public c(La/b/o/i/g;)Z
    .locals 2

    iget-object v0, p0, La/b/k/h$c;->b:La/b/k/h;

    invoke-virtual {v0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v0

    if-eqz v0, :cond_0

    const/16 v1, 0x6c

    invoke-interface {v0, v1, p1}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    :cond_0
    const/4 p1, 0x1

    return p1
.end method
