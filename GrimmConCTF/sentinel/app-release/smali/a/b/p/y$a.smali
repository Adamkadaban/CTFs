.class public La/b/p/y$a;
.super La/f/d/b/e;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = La/b/p/y;->l(Landroid/content/Context;La/b/p/x0;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:I

.field public final synthetic b:I

.field public final synthetic c:Ljava/lang/ref/WeakReference;

.field public final synthetic d:La/b/p/y;


# direct methods
.method public constructor <init>(La/b/p/y;IILjava/lang/ref/WeakReference;)V
    .locals 0

    iput-object p1, p0, La/b/p/y$a;->d:La/b/p/y;

    iput p2, p0, La/b/p/y$a;->a:I

    iput p3, p0, La/b/p/y$a;->b:I

    iput-object p4, p0, La/b/p/y$a;->c:Ljava/lang/ref/WeakReference;

    invoke-direct {p0}, La/f/d/b/e;-><init>()V

    return-void
.end method


# virtual methods
.method public c(Landroid/graphics/Typeface;)V
    .locals 3

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_1

    iget v0, p0, La/b/p/y$a;->a:I

    const/4 v1, -0x1

    if-eq v0, v1, :cond_1

    iget v1, p0, La/b/p/y$a;->b:I

    and-int/lit8 v1, v1, 0x2

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-static {p1, v0, v1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    move-result-object p1

    :cond_1
    iget-object v0, p0, La/b/p/y$a;->d:La/b/p/y;

    iget-object v1, p0, La/b/p/y$a;->c:Ljava/lang/ref/WeakReference;

    .line 1
    iget-boolean v2, v0, La/b/p/y;->m:Z

    if-eqz v2, :cond_2

    iput-object p1, v0, La/b/p/y;->l:Landroid/graphics/Typeface;

    invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    if-eqz v1, :cond_2

    iget v0, v0, La/b/p/y;->j:I

    invoke-virtual {v1, p1, v0}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    :cond_2
    return-void
.end method
