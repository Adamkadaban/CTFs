.class public La/i/a/j$a;
.super La/a/b;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/i/a/j;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic c:La/i/a/j;


# direct methods
.method public constructor <init>(La/i/a/j;Z)V
    .locals 0

    iput-object p1, p0, La/i/a/j$a;->c:La/i/a/j;

    invoke-direct {p0, p2}, La/a/b;-><init>(Z)V

    return-void
.end method
