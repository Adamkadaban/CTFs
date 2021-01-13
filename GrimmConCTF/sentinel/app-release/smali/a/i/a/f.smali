.class public La/i/a/f;
.super Ljava/lang/Object;
.source ""


# instance fields
.field public final a:La/i/a/h;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/i/a/h<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(La/i/a/h;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/i/a/h<",
            "*>;)V"
        }
    .end annotation

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La/i/a/f;->a:La/i/a/h;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    iget-object v0, p0, La/i/a/f;->a:La/i/a/h;

    iget-object v0, v0, La/i/a/h;->f:La/i/a/j;

    invoke-virtual {v0}, La/i/a/j;->a0()V

    return-void
.end method
