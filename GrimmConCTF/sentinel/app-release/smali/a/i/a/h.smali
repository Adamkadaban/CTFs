.class public abstract La/i/a/h;
.super La/i/a/e;
.source ""


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "La/i/a/e;"
    }
.end annotation


# instance fields
.field public final b:Landroid/app/Activity;

.field public final c:Landroid/content/Context;

.field public final d:Landroid/os/Handler;

.field public final e:I

.field public final f:La/i/a/j;


# direct methods
.method public constructor <init>(La/i/a/d;)V
    .locals 2

    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    .line 1
    invoke-direct {p0}, La/i/a/e;-><init>()V

    new-instance v1, La/i/a/j;

    invoke-direct {v1}, La/i/a/j;-><init>()V

    iput-object v1, p0, La/i/a/h;->f:La/i/a/j;

    iput-object p1, p0, La/i/a/h;->b:Landroid/app/Activity;

    const-string v1, "context == null"

    invoke-static {p1, v1}, La/b/k/h$i;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, La/i/a/h;->c:Landroid/content/Context;

    const-string p1, "handler == null"

    invoke-static {v0, p1}, La/b/k/h$i;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iput-object v0, p0, La/i/a/h;->d:Landroid/os/Handler;

    const/4 p1, 0x0

    iput p1, p0, La/i/a/h;->e:I

    return-void
.end method
