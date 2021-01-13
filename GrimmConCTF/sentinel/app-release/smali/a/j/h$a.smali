.class public La/j/h$a;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/j/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field public a:La/j/d$b;

.field public b:La/j/e;


# direct methods
.method public constructor <init>(La/j/f;La/j/d$b;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, La/j/j;->d(Ljava/lang/Object;)La/j/e;

    move-result-object p1

    iput-object p1, p0, La/j/h$a;->b:La/j/e;

    iput-object p2, p0, La/j/h$a;->a:La/j/d$b;

    return-void
.end method


# virtual methods
.method public a(La/j/g;La/j/d$a;)V
    .locals 2

    invoke-static {p2}, La/j/h;->c(La/j/d$a;)La/j/d$b;

    move-result-object v0

    iget-object v1, p0, La/j/h$a;->a:La/j/d$b;

    invoke-static {v1, v0}, La/j/h;->e(La/j/d$b;La/j/d$b;)La/j/d$b;

    move-result-object v1

    iput-object v1, p0, La/j/h$a;->a:La/j/d$b;

    iget-object v1, p0, La/j/h$a;->b:La/j/e;

    invoke-interface {v1, p1, p2}, La/j/e;->g(La/j/g;La/j/d$a;)V

    iput-object v0, p0, La/j/h$a;->a:La/j/d$b;

    return-void
.end method
