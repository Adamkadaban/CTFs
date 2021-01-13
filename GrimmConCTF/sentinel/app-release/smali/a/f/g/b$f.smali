.class public La/f/g/b$f;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/g/b;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "f"
.end annotation


# instance fields
.field public final a:Landroid/net/Uri;

.field public final b:I

.field public final c:I

.field public final d:Z

.field public final e:I


# direct methods
.method public constructor <init>(Landroid/net/Uri;IIZI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    iput-object p1, p0, La/f/g/b$f;->a:Landroid/net/Uri;

    iput p2, p0, La/f/g/b$f;->b:I

    iput p3, p0, La/f/g/b$f;->c:I

    iput-boolean p4, p0, La/f/g/b$f;->d:Z

    iput p5, p0, La/f/g/b$f;->e:I

    return-void

    :cond_0
    const/4 p1, 0x0

    .line 1
    throw p1
.end method
