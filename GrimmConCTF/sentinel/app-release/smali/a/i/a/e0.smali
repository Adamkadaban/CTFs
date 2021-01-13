.class public La/i/a/e0;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/j/g;


# instance fields
.field public b:La/j/h;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, La/i/a/e0;->b:La/j/h;

    return-void
.end method


# virtual methods
.method public a()La/j/d;
    .locals 1

    .line 1
    iget-object v0, p0, La/i/a/e0;->b:La/j/h;

    if-nez v0, :cond_0

    new-instance v0, La/j/h;

    invoke-direct {v0, p0}, La/j/h;-><init>(La/j/g;)V

    iput-object v0, p0, La/i/a/e0;->b:La/j/h;

    .line 2
    :cond_0
    iget-object v0, p0, La/i/a/e0;->b:La/j/h;

    return-object v0
.end method
