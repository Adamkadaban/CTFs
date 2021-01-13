.class public La/e/b/h/j;
.super La/e/b/h/h;
.source ""


# instance fields
.field public q0:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, La/e/b/h/h;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, La/e/b/h/j;->q0:Z

    return-void
.end method


# virtual methods
.method public a(La/e/b/h/e;)V
    .locals 2

    const/4 p1, 0x0

    .line 1
    :goto_0
    iget v0, p0, La/e/b/h/h;->p0:I

    if-ge p1, v0, :cond_1

    iget-object v0, p0, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v0, v0, p1

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    .line 2
    iput-boolean v1, v0, La/e/b/h/d;->C:Z

    :cond_0
    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method
