.class public La/f/j/t$c;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/j/t;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# instance fields
.field public final a:La/f/j/t;


# direct methods
.method public constructor <init>()V
    .locals 2

    new-instance v0, La/f/j/t;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, La/f/j/t;-><init>(La/f/j/t;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, La/f/j/t$c;->a:La/f/j/t;

    return-void
.end method


# virtual methods
.method public abstract a()La/f/j/t;
.end method

.method public b(La/f/e/b;)V
    .locals 0

    return-void
.end method

.method public abstract c(La/f/e/b;)V
.end method
