.class public La/b/p/c$e;
.super La/b/o/i/l;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/p/c;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "e"
.end annotation


# instance fields
.field public final synthetic m:La/b/p/c;


# direct methods
.method public constructor <init>(La/b/p/c;Landroid/content/Context;La/b/o/i/g;Landroid/view/View;Z)V
    .locals 7

    iput-object p1, p0, La/b/p/c$e;->m:La/b/p/c;

    sget v5, La/b/a;->actionOverflowMenuStyle:I

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p2

    move-object v2, p3

    move-object v3, p4

    move v4, p5

    .line 1
    invoke-direct/range {v0 .. v6}, La/b/o/i/l;-><init>(Landroid/content/Context;La/b/o/i/g;Landroid/view/View;ZII)V

    const p2, 0x800005

    .line 2
    iput p2, p0, La/b/o/i/l;->g:I

    .line 3
    iget-object p1, p1, La/b/p/c;->y:La/b/p/c$f;

    invoke-virtual {p0, p1}, La/b/o/i/l;->d(La/b/o/i/m$a;)V

    return-void
.end method


# virtual methods
.method public c()V
    .locals 2

    iget-object v0, p0, La/b/p/c$e;->m:La/b/p/c;

    .line 1
    iget-object v0, v0, La/b/o/i/b;->d:La/b/o/i/g;

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    .line 2
    invoke-virtual {v0, v1}, La/b/o/i/g;->c(Z)V

    .line 3
    :cond_0
    iget-object v0, p0, La/b/p/c$e;->m:La/b/p/c;

    const/4 v1, 0x0

    iput-object v1, v0, La/b/p/c;->u:La/b/p/c$e;

    invoke-super {p0}, La/b/o/i/l;->c()V

    return-void
.end method
