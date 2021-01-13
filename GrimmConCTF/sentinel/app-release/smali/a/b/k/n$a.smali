.class public La/b/k/n$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/f/j/d$a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/n;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:La/b/k/n;


# direct methods
.method public constructor <init>(La/b/k/n;)V
    .locals 0

    iput-object p1, p0, La/b/k/n$a;->b:La/b/k/n;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public h(Landroid/view/KeyEvent;)Z
    .locals 1

    iget-object v0, p0, La/b/k/n$a;->b:La/b/k/n;

    invoke-virtual {v0, p1}, La/b/k/n;->c(Landroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method
