.class public La/e/b/h/l/n$a;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/e/b/h/l/n;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# direct methods
.method public constructor <init>(La/e/b/h/l/n;La/e/b/h/d;La/e/b/d;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/lang/ref/WeakReference;

    invoke-direct {p1, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iget-object p1, p2, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {p3, p1}, La/e/b/d;->o(Ljava/lang/Object;)I

    iget-object p1, p2, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {p3, p1}, La/e/b/d;->o(Ljava/lang/Object;)I

    iget-object p1, p2, La/e/b/h/d;->H:La/e/b/h/c;

    invoke-virtual {p3, p1}, La/e/b/d;->o(Ljava/lang/Object;)I

    iget-object p1, p2, La/e/b/h/d;->I:La/e/b/h/c;

    invoke-virtual {p3, p1}, La/e/b/d;->o(Ljava/lang/Object;)I

    iget-object p1, p2, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {p3, p1}, La/e/b/d;->o(Ljava/lang/Object;)I

    return-void
.end method
