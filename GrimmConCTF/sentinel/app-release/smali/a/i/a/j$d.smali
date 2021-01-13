.class public La/i/a/j$d;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/i/a/j;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "d"
.end annotation


# instance fields
.field public final a:Landroid/view/animation/Animation;

.field public final b:Landroid/animation/Animator;


# direct methods
.method public constructor <init>(Landroid/animation/Animator;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, La/i/a/j$d;->a:Landroid/view/animation/Animation;

    iput-object p1, p0, La/i/a/j$d;->b:Landroid/animation/Animator;

    return-void
.end method

.method public constructor <init>(Landroid/view/animation/Animation;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La/i/a/j$d;->a:Landroid/view/animation/Animation;

    const/4 p1, 0x0

    iput-object p1, p0, La/i/a/j$d;->b:Landroid/animation/Animator;

    return-void
.end method
