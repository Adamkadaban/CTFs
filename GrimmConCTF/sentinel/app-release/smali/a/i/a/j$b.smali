.class public La/i/a/j$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/i/a/j;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:La/i/a/j;


# direct methods
.method public constructor <init>(La/i/a/j;)V
    .locals 0

    iput-object p1, p0, La/i/a/j$b;->b:La/i/a/j;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 1

    iget-object v0, p0, La/i/a/j$b;->b:La/i/a/j;

    invoke-virtual {v0}, La/i/a/j;->L()Z

    return-void
.end method
