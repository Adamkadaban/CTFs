.class public La/b/k/h;
.super La/b/k/g;
.source ""

# interfaces
.implements La/b/o/i/g$a;
.implements Landroid/view/LayoutInflater$Factory2;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/k/h$i;,
        La/b/k/h$f;,
        La/b/k/h$h;,
        La/b/k/h$g;,
        La/b/k/h$e;,
        La/b/k/h$j;,
        La/b/k/h$k;,
        La/b/k/h$c;,
        La/b/k/h$l;,
        La/b/k/h$d;
    }
.end annotation


# static fields
.field public static final a0:La/d/h;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "La/d/h<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field public static final b0:Z = false

.field public static final c0:[I

.field public static final d0:Z

.field public static final e0:Z

.field public static f0:Z


# instance fields
.field public A:Z

.field public B:Z

.field public C:Z

.field public D:Z

.field public E:Z

.field public F:Z

.field public G:[La/b/k/h$k;

.field public H:La/b/k/h$k;

.field public I:Z

.field public J:Z

.field public K:Z

.field public L:Z

.field public M:Z

.field public N:I

.field public O:I

.field public P:Z

.field public Q:Z

.field public R:La/b/k/h$g;

.field public S:La/b/k/h$g;

.field public T:Z

.field public U:I

.field public final V:Ljava/lang/Runnable;

.field public W:Z

.field public X:Landroid/graphics/Rect;

.field public Y:Landroid/graphics/Rect;

.field public Z:La/b/k/o;

.field public final d:Ljava/lang/Object;

.field public final e:Landroid/content/Context;

.field public f:Landroid/view/Window;

.field public g:La/b/k/h$e;

.field public final h:La/b/k/f;

.field public i:La/b/k/a;

.field public j:Landroid/view/MenuInflater;

.field public k:Ljava/lang/CharSequence;

.field public l:La/b/p/c0;

.field public m:La/b/k/h$c;

.field public n:La/b/k/h$l;

.field public o:La/b/o/a;

.field public p:Landroidx/appcompat/widget/ActionBarContextView;

.field public q:Landroid/widget/PopupWindow;

.field public r:Ljava/lang/Runnable;

.field public s:La/f/j/p;

.field public t:Z

.field public u:Z

.field public v:Landroid/view/ViewGroup;

.field public w:Landroid/widget/TextView;

.field public x:Landroid/view/View;

.field public y:Z

.field public z:Z


# direct methods
.method public static constructor <clinit>()V
    .locals 4

    new-instance v0, La/d/h;

    invoke-direct {v0}, La/d/h;-><init>()V

    sput-object v0, La/b/k/h;->a0:La/d/h;

    const/4 v0, 0x1

    new-array v1, v0, [I

    const/4 v2, 0x0

    const v3, 0x1010054

    aput v3, v1, v2

    sput-object v1, La/b/k/h;->c0:[I

    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    const-string v2, "robolectric"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    xor-int/2addr v1, v0

    sput-boolean v1, La/b/k/h;->d0:Z

    sput-boolean v0, La/b/k/h;->e0:Z

    sget-boolean v1, La/b/k/h;->b0:Z

    if-eqz v1, :cond_0

    sget-boolean v1, La/b/k/h;->f0:Z

    if-nez v1, :cond_0

    invoke-static {}, Ljava/lang/Thread;->getDefaultUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v1

    new-instance v2, La/b/k/h$a;

    invoke-direct {v2, v1}, La/b/k/h$a;-><init>(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    invoke-static {v2}, Ljava/lang/Thread;->setDefaultUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    sput-boolean v0, La/b/k/h;->f0:Z

    :cond_0
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/Window;La/b/k/f;Ljava/lang/Object;)V
    .locals 3

    invoke-direct {p0}, La/b/k/g;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, La/b/k/h;->s:La/f/j/p;

    const/4 v1, 0x1

    iput-boolean v1, p0, La/b/k/h;->t:Z

    const/16 v1, -0x64

    iput v1, p0, La/b/k/h;->N:I

    new-instance v2, La/b/k/h$b;

    invoke-direct {v2, p0}, La/b/k/h$b;-><init>(La/b/k/h;)V

    iput-object v2, p0, La/b/k/h;->V:Ljava/lang/Runnable;

    iput-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    iput-object p3, p0, La/b/k/h;->h:La/b/k/f;

    iput-object p4, p0, La/b/k/h;->d:Ljava/lang/Object;

    iget p3, p0, La/b/k/h;->N:I

    if-ne p3, v1, :cond_2

    instance-of p3, p4, Landroid/app/Dialog;

    if-eqz p3, :cond_2

    :goto_0
    if-eqz p1, :cond_1

    .line 1
    instance-of p3, p1, La/b/k/e;

    if-eqz p3, :cond_0

    check-cast p1, La/b/k/e;

    goto :goto_1

    :cond_0
    instance-of p3, p1, Landroid/content/ContextWrapper;

    if-eqz p3, :cond_1

    check-cast p1, Landroid/content/ContextWrapper;

    invoke-virtual {p1}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object p1

    goto :goto_0

    :cond_1
    move-object p1, v0

    :goto_1
    if-eqz p1, :cond_2

    .line 2
    invoke-virtual {p1}, La/b/k/e;->o()La/b/k/g;

    move-result-object p1

    check-cast p1, La/b/k/h;

    .line 3
    iget p1, p1, La/b/k/h;->N:I

    .line 4
    iput p1, p0, La/b/k/h;->N:I

    :cond_2
    iget p1, p0, La/b/k/h;->N:I

    if-ne p1, v1, :cond_3

    sget-object p1, La/b/k/h;->a0:La/d/h;

    iget-object p3, p0, La/b/k/h;->d:Ljava/lang/Object;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p3

    .line 5
    invoke-virtual {p1, p3, v0}, La/d/h;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    .line 6
    check-cast p1, Ljava/lang/Integer;

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iput p1, p0, La/b/k/h;->N:I

    sget-object p1, La/b/k/h;->a0:La/d/h;

    iget-object p3, p0, La/b/k/h;->d:Ljava/lang/Object;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p3}, La/d/h;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    if-eqz p2, :cond_4

    invoke-virtual {p0, p2}, La/b/k/h;->r(Landroid/view/Window;)V

    :cond_4
    invoke-static {}, La/b/p/j;->d()V

    return-void
.end method


# virtual methods
.method public final A()V
    .locals 2

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_0

    check-cast v0, Landroid/app/Activity;

    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-virtual {p0, v0}, La/b/k/h;->r(Landroid/view/Window;)V

    :cond_0
    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    if-eqz v0, :cond_1

    return-void

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "We have not been given a Window"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public B(Landroid/view/Menu;)La/b/k/h$k;
    .locals 5

    iget-object v0, p0, La/b/k/h;->G:[La/b/k/h$k;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    array-length v2, v0

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    if-ge v1, v2, :cond_2

    aget-object v3, v0, v1

    if-eqz v3, :cond_1

    iget-object v4, v3, La/b/k/h$k;->h:La/b/o/i/g;

    if-ne v4, p1, :cond_1

    return-object v3

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    return-object p1
.end method

.method public final C(Landroid/content/Context;)La/b/k/h$g;
    .locals 3

    iget-object v0, p0, La/b/k/h;->R:La/b/k/h$g;

    if-nez v0, :cond_1

    new-instance v0, La/b/k/h$h;

    .line 1
    sget-object v1, La/b/k/q;->d:La/b/k/q;

    if-nez v1, :cond_0

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    new-instance v1, La/b/k/q;

    const-string v2, "location"

    invoke-virtual {p1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/location/LocationManager;

    invoke-direct {v1, p1, v2}, La/b/k/q;-><init>(Landroid/content/Context;Landroid/location/LocationManager;)V

    sput-object v1, La/b/k/q;->d:La/b/k/q;

    :cond_0
    sget-object p1, La/b/k/q;->d:La/b/k/q;

    .line 2
    invoke-direct {v0, p0, p1}, La/b/k/h$h;-><init>(La/b/k/h;La/b/k/q;)V

    iput-object v0, p0, La/b/k/h;->R:La/b/k/h$g;

    :cond_1
    iget-object p1, p0, La/b/k/h;->R:La/b/k/h$g;

    return-object p1
.end method

.method public D(I)La/b/k/h$k;
    .locals 4

    iget-object v0, p0, La/b/k/h;->G:[La/b/k/h$k;

    if-eqz v0, :cond_0

    array-length v1, v0

    if-gt v1, p1, :cond_2

    :cond_0
    add-int/lit8 v1, p1, 0x1

    new-array v1, v1, [La/b/k/h$k;

    if-eqz v0, :cond_1

    array-length v2, v0

    const/4 v3, 0x0

    invoke-static {v0, v3, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    :cond_1
    iput-object v1, p0, La/b/k/h;->G:[La/b/k/h$k;

    move-object v0, v1

    :cond_2
    aget-object v1, v0, p1

    if-nez v1, :cond_3

    new-instance v1, La/b/k/h$k;

    invoke-direct {v1, p1}, La/b/k/h$k;-><init>(I)V

    aput-object v1, v0, p1

    :cond_3
    return-object v1
.end method

.method public final E()Landroid/view/Window$Callback;
    .locals 1

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    move-result-object v0

    return-object v0
.end method

.method public final F()V
    .locals 3

    invoke-virtual {p0}, La/b/k/h;->z()V

    iget-boolean v0, p0, La/b/k/h;->A:Z

    if-eqz v0, :cond_3

    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_0

    goto :goto_2

    :cond_0
    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_1

    new-instance v0, La/b/k/r;

    iget-object v1, p0, La/b/k/h;->d:Ljava/lang/Object;

    check-cast v1, Landroid/app/Activity;

    iget-boolean v2, p0, La/b/k/h;->B:Z

    invoke-direct {v0, v1, v2}, La/b/k/r;-><init>(Landroid/app/Activity;Z)V

    :goto_0
    iput-object v0, p0, La/b/k/h;->i:La/b/k/a;

    goto :goto_1

    :cond_1
    instance-of v0, v0, Landroid/app/Dialog;

    if-eqz v0, :cond_2

    new-instance v0, La/b/k/r;

    iget-object v1, p0, La/b/k/h;->d:Ljava/lang/Object;

    check-cast v1, Landroid/app/Dialog;

    invoke-direct {v0, v1}, La/b/k/r;-><init>(Landroid/app/Dialog;)V

    goto :goto_0

    :cond_2
    :goto_1
    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_3

    iget-boolean v1, p0, La/b/k/h;->W:Z

    invoke-virtual {v0, v1}, La/b/k/a;->g(Z)V

    :cond_3
    :goto_2
    return-void
.end method

.method public final G(I)V
    .locals 2

    iget v0, p0, La/b/k/h;->U:I

    const/4 v1, 0x1

    shl-int p1, v1, p1

    or-int/2addr p1, v0

    iput p1, p0, La/b/k/h;->U:I

    iget-boolean p1, p0, La/b/k/h;->T:Z

    if-nez p1, :cond_0

    iget-object p1, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    iget-object v0, p0, La/b/k/h;->V:Ljava/lang/Runnable;

    invoke-static {p1, v0}, La/f/j/k;->q(Landroid/view/View;Ljava/lang/Runnable;)V

    iput-boolean v1, p0, La/b/k/h;->T:Z

    :cond_0
    return-void
.end method

.method public H(Landroid/content/Context;I)I
    .locals 2

    const/16 v0, -0x64

    const/4 v1, -0x1

    if-eq p2, v0, :cond_5

    if-eq p2, v1, :cond_4

    if-eqz p2, :cond_2

    const/4 v0, 0x1

    if-eq p2, v0, :cond_4

    const/4 v0, 0x2

    if-eq p2, v0, :cond_4

    const/4 v0, 0x3

    if-ne p2, v0, :cond_1

    .line 1
    iget-object p2, p0, La/b/k/h;->S:La/b/k/h$g;

    if-nez p2, :cond_0

    new-instance p2, La/b/k/h$f;

    invoke-direct {p2, p0, p1}, La/b/k/h$f;-><init>(La/b/k/h;Landroid/content/Context;)V

    iput-object p2, p0, La/b/k/h;->S:La/b/k/h$g;

    :cond_0
    iget-object p1, p0, La/b/k/h;->S:La/b/k/h$g;

    .line 2
    :goto_0
    invoke-virtual {p1}, La/b/k/h$g;->c()I

    move-result p1

    return p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Unknown value set for night mode. Please use one of the MODE_NIGHT values from AppCompatDelegate."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p2

    const-class v0, Landroid/app/UiModeManager;

    invoke-virtual {p2, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Landroid/app/UiModeManager;

    invoke-virtual {p2}, Landroid/app/UiModeManager;->getNightMode()I

    move-result p2

    if-nez p2, :cond_3

    return v1

    :cond_3
    invoke-virtual {p0, p1}, La/b/k/h;->C(Landroid/content/Context;)La/b/k/h$g;

    move-result-object p1

    goto :goto_0

    :cond_4
    return p2

    :cond_5
    return v1
.end method

.method public final I(La/b/k/h$k;Landroid/view/KeyEvent;)V
    .locals 13

    iget-boolean v0, p1, La/b/k/h$k;->m:Z

    if-nez v0, :cond_1e

    iget-boolean v0, p0, La/b/k/h;->M:Z

    if-eqz v0, :cond_0

    goto/16 :goto_e

    :cond_0
    iget v0, p1, La/b/k/h$k;->a:I

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-nez v0, :cond_2

    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v0

    iget v0, v0, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit8 v0, v0, 0xf

    const/4 v3, 0x4

    if-ne v0, v3, :cond_1

    move v0, v2

    goto :goto_0

    :cond_1
    move v0, v1

    :goto_0
    if-eqz v0, :cond_2

    return-void

    :cond_2
    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v0

    if-eqz v0, :cond_3

    iget v3, p1, La/b/k/h$k;->a:I

    iget-object v4, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-interface {v0, v3, v4}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    move-result v0

    if-nez v0, :cond_3

    invoke-virtual {p0, p1, v2}, La/b/k/h;->u(La/b/k/h$k;Z)V

    return-void

    :cond_3
    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    const-string v3, "window"

    invoke-virtual {v0, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/WindowManager;

    if-nez v0, :cond_4

    return-void

    :cond_4
    invoke-virtual {p0, p1, p2}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    move-result p2

    if-nez p2, :cond_5

    return-void

    :cond_5
    iget-object p2, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    const/4 v3, -0x1

    const/4 v4, -0x2

    if-eqz p2, :cond_7

    iget-boolean p2, p1, La/b/k/h$k;->o:Z

    if-eqz p2, :cond_6

    goto :goto_1

    :cond_6
    iget-object p2, p1, La/b/k/h$k;->g:Landroid/view/View;

    if-eqz p2, :cond_1c

    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p2

    if-eqz p2, :cond_1c

    iget p2, p2, Landroid/view/ViewGroup$LayoutParams;->width:I

    if-ne p2, v3, :cond_1c

    move v6, v3

    goto/16 :goto_c

    :cond_7
    :goto_1
    iget-object p2, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    const/4 v3, 0x0

    if-nez p2, :cond_c

    .line 1
    invoke-virtual {p0}, La/b/k/h;->F()V

    iget-object p2, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz p2, :cond_8

    .line 2
    invoke-virtual {p2}, La/b/k/a;->d()Landroid/content/Context;

    move-result-object p2

    goto :goto_2

    :cond_8
    move-object p2, v3

    :goto_2
    if-nez p2, :cond_9

    iget-object p2, p0, La/b/k/h;->e:Landroid/content/Context;

    .line 3
    :cond_9
    new-instance v5, Landroid/util/TypedValue;

    invoke-direct {v5}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    invoke-virtual {v6}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    move-result-object v6

    invoke-virtual {p2}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v7

    invoke-virtual {v6, v7}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    sget v7, La/b/a;->actionBarPopupTheme:I

    invoke-virtual {v6, v7, v5, v2}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v7, v5, Landroid/util/TypedValue;->resourceId:I

    if-eqz v7, :cond_a

    invoke-virtual {v6, v7, v2}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    :cond_a
    sget v7, La/b/a;->panelMenuListTheme:I

    invoke-virtual {v6, v7, v5, v2}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v5, v5, Landroid/util/TypedValue;->resourceId:I

    if-eqz v5, :cond_b

    goto :goto_3

    :cond_b
    sget v5, La/b/i;->Theme_AppCompat_CompactMenu:I

    :goto_3
    invoke-virtual {v6, v5, v2}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    new-instance v5, La/b/o/c;

    invoke-direct {v5, p2, v1}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v5}, La/b/o/c;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p2

    invoke-virtual {p2, v6}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    iput-object v5, p1, La/b/k/h$k;->j:Landroid/content/Context;

    sget-object p2, La/b/j;->AppCompatTheme:[I

    invoke-virtual {v5, p2}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object p2

    sget v5, La/b/j;->AppCompatTheme_panelBackground:I

    invoke-virtual {p2, v5, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v5

    iput v5, p1, La/b/k/h$k;->b:I

    sget v5, La/b/j;->AppCompatTheme_android_windowAnimationStyle:I

    invoke-virtual {p2, v5, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v5

    iput v5, p1, La/b/k/h$k;->d:I

    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 4
    new-instance p2, La/b/k/h$j;

    iget-object v5, p1, La/b/k/h$k;->j:Landroid/content/Context;

    invoke-direct {p2, p0, v5}, La/b/k/h$j;-><init>(La/b/k/h;Landroid/content/Context;)V

    iput-object p2, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    const/16 p2, 0x51

    iput p2, p1, La/b/k/h$k;->c:I

    goto :goto_4

    .line 5
    :cond_c
    iget-boolean v5, p1, La/b/k/h$k;->o:Z

    if-eqz v5, :cond_d

    invoke-virtual {p2}, Landroid/view/ViewGroup;->getChildCount()I

    move-result p2

    if-lez p2, :cond_d

    iget-object p2, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    invoke-virtual {p2}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 6
    :cond_d
    :goto_4
    iget-object p2, p1, La/b/k/h$k;->g:Landroid/view/View;

    if-eqz p2, :cond_e

    iput-object p2, p1, La/b/k/h$k;->f:Landroid/view/View;

    goto :goto_6

    :cond_e
    iget-object p2, p1, La/b/k/h$k;->h:La/b/o/i/g;

    if-nez p2, :cond_f

    goto :goto_7

    :cond_f
    iget-object p2, p0, La/b/k/h;->n:La/b/k/h$l;

    if-nez p2, :cond_10

    new-instance p2, La/b/k/h$l;

    invoke-direct {p2, p0}, La/b/k/h$l;-><init>(La/b/k/h;)V

    iput-object p2, p0, La/b/k/h;->n:La/b/k/h$l;

    :cond_10
    iget-object p2, p0, La/b/k/h;->n:La/b/k/h$l;

    .line 7
    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    if-nez v5, :cond_11

    goto :goto_5

    :cond_11
    iget-object v3, p1, La/b/k/h$k;->i:La/b/o/i/e;

    if-nez v3, :cond_12

    new-instance v3, La/b/o/i/e;

    iget-object v5, p1, La/b/k/h$k;->j:Landroid/content/Context;

    sget v6, La/b/g;->abc_list_menu_item_layout:I

    invoke-direct {v3, v5, v6}, La/b/o/i/e;-><init>(Landroid/content/Context;I)V

    iput-object v3, p1, La/b/k/h$k;->i:La/b/o/i/e;

    .line 8
    iput-object p2, v3, La/b/o/i/e;->i:La/b/o/i/m$a;

    .line 9
    iget-object p2, p1, La/b/k/h$k;->h:La/b/o/i/g;

    .line 10
    iget-object v5, p2, La/b/o/i/g;->a:Landroid/content/Context;

    invoke-virtual {p2, v3, v5}, La/b/o/i/g;->b(La/b/o/i/m;Landroid/content/Context;)V

    .line 11
    :cond_12
    iget-object p2, p1, La/b/k/h$k;->i:La/b/o/i/e;

    iget-object v3, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    .line 12
    iget-object v5, p2, La/b/o/i/e;->e:Landroidx/appcompat/view/menu/ExpandedMenuView;

    if-nez v5, :cond_14

    iget-object v5, p2, La/b/o/i/e;->c:Landroid/view/LayoutInflater;

    sget v6, La/b/g;->abc_expanded_menu_layout:I

    invoke-virtual {v5, v6, v3, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/ExpandedMenuView;

    iput-object v3, p2, La/b/o/i/e;->e:Landroidx/appcompat/view/menu/ExpandedMenuView;

    iget-object v3, p2, La/b/o/i/e;->j:La/b/o/i/e$a;

    if-nez v3, :cond_13

    new-instance v3, La/b/o/i/e$a;

    invoke-direct {v3, p2}, La/b/o/i/e$a;-><init>(La/b/o/i/e;)V

    iput-object v3, p2, La/b/o/i/e;->j:La/b/o/i/e$a;

    :cond_13
    iget-object v3, p2, La/b/o/i/e;->e:Landroidx/appcompat/view/menu/ExpandedMenuView;

    iget-object v5, p2, La/b/o/i/e;->j:La/b/o/i/e$a;

    invoke-virtual {v3, v5}, Landroid/widget/ListView;->setAdapter(Landroid/widget/ListAdapter;)V

    iget-object v3, p2, La/b/o/i/e;->e:Landroidx/appcompat/view/menu/ExpandedMenuView;

    invoke-virtual {v3, p2}, Landroid/widget/ListView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    :cond_14
    iget-object v3, p2, La/b/o/i/e;->e:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 13
    :goto_5
    iput-object v3, p1, La/b/k/h$k;->f:Landroid/view/View;

    if-eqz v3, :cond_15

    :goto_6
    move p2, v2

    goto :goto_8

    :cond_15
    :goto_7
    move p2, v1

    :goto_8
    if-eqz p2, :cond_1d

    .line 14
    iget-object p2, p1, La/b/k/h$k;->f:Landroid/view/View;

    if-nez p2, :cond_16

    goto :goto_a

    :cond_16
    iget-object p2, p1, La/b/k/h$k;->g:Landroid/view/View;

    if-eqz p2, :cond_17

    goto :goto_9

    :cond_17
    iget-object p2, p1, La/b/k/h$k;->i:La/b/o/i/e;

    invoke-virtual {p2}, La/b/o/i/e;->a()Landroid/widget/ListAdapter;

    move-result-object p2

    check-cast p2, La/b/o/i/e$a;

    invoke-virtual {p2}, La/b/o/i/e$a;->getCount()I

    move-result p2

    if-lez p2, :cond_18

    :goto_9
    move p2, v2

    goto :goto_b

    :cond_18
    :goto_a
    move p2, v1

    :goto_b
    if-nez p2, :cond_19

    goto :goto_d

    .line 15
    :cond_19
    iget-object p2, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p2

    if-nez p2, :cond_1a

    new-instance p2, Landroid/view/ViewGroup$LayoutParams;

    invoke-direct {p2, v4, v4}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    :cond_1a
    iget v3, p1, La/b/k/h$k;->b:I

    iget-object v5, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    invoke-virtual {v5, v3}, Landroid/view/ViewGroup;->setBackgroundResource(I)V

    iget-object v3, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {v3}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v3

    instance-of v5, v3, Landroid/view/ViewGroup;

    if-eqz v5, :cond_1b

    check-cast v3, Landroid/view/ViewGroup;

    iget-object v5, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {v3, v5}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_1b
    iget-object v3, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    iget-object v5, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {v3, v5, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iget-object p2, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {p2}, Landroid/view/View;->hasFocus()Z

    move-result p2

    if-nez p2, :cond_1c

    iget-object p2, p1, La/b/k/h$k;->f:Landroid/view/View;

    invoke-virtual {p2}, Landroid/view/View;->requestFocus()Z

    :cond_1c
    move v6, v4

    :goto_c
    iput-boolean v1, p1, La/b/k/h$k;->l:Z

    new-instance p2, Landroid/view/WindowManager$LayoutParams;

    const/4 v7, -0x2

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/16 v10, 0x3ea

    const/high16 v11, 0x820000

    const/4 v12, -0x3

    move-object v5, p2

    invoke-direct/range {v5 .. v12}, Landroid/view/WindowManager$LayoutParams;-><init>(IIIIIII)V

    iget v1, p1, La/b/k/h$k;->c:I

    iput v1, p2, Landroid/view/WindowManager$LayoutParams;->gravity:I

    iget v1, p1, La/b/k/h$k;->d:I

    iput v1, p2, Landroid/view/WindowManager$LayoutParams;->windowAnimations:I

    iget-object v1, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    invoke-interface {v0, v1, p2}, Landroid/view/WindowManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iput-boolean v2, p1, La/b/k/h$k;->m:Z

    return-void

    :cond_1d
    :goto_d
    iput-boolean v2, p1, La/b/k/h$k;->o:Z

    :cond_1e
    :goto_e
    return-void
.end method

.method public final J(La/b/k/h$k;ILandroid/view/KeyEvent;I)Z
    .locals 2

    invoke-virtual {p3}, Landroid/view/KeyEvent;->isSystem()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    iget-boolean v0, p1, La/b/k/h$k;->k:Z

    if-nez v0, :cond_1

    invoke-virtual {p0, p1, p3}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_2

    :cond_1
    iget-object v0, p1, La/b/k/h$k;->h:La/b/o/i/g;

    if-eqz v0, :cond_2

    invoke-virtual {v0, p2, p3, p4}, La/b/o/i/g;->performShortcut(ILandroid/view/KeyEvent;I)Z

    move-result v1

    :cond_2
    if-eqz v1, :cond_3

    const/4 p2, 0x1

    and-int/lit8 p3, p4, 0x1

    if-nez p3, :cond_3

    iget-object p3, p0, La/b/k/h;->l:La/b/p/c0;

    if-nez p3, :cond_3

    invoke-virtual {p0, p1, p2}, La/b/k/h;->u(La/b/k/h$k;Z)V

    :cond_3
    return v1
.end method

.method public final K(La/b/k/h$k;Landroid/view/KeyEvent;)Z
    .locals 10

    iget-boolean v0, p0, La/b/k/h;->M:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    iget-boolean v0, p1, La/b/k/h$k;->k:Z

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    return v2

    :cond_1
    iget-object v0, p0, La/b/k/h;->H:La/b/k/h$k;

    if-eqz v0, :cond_2

    if-eq v0, p1, :cond_2

    invoke-virtual {p0, v0, v1}, La/b/k/h;->u(La/b/k/h$k;Z)V

    :cond_2
    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v0

    if-eqz v0, :cond_3

    iget v3, p1, La/b/k/h$k;->a:I

    invoke-interface {v0, v3}, Landroid/view/Window$Callback;->onCreatePanelView(I)Landroid/view/View;

    move-result-object v3

    iput-object v3, p1, La/b/k/h$k;->g:Landroid/view/View;

    :cond_3
    iget v3, p1, La/b/k/h$k;->a:I

    const/16 v4, 0x6c

    if-eqz v3, :cond_5

    if-ne v3, v4, :cond_4

    goto :goto_0

    :cond_4
    move v3, v1

    goto :goto_1

    :cond_5
    :goto_0
    move v3, v2

    :goto_1
    if-eqz v3, :cond_6

    iget-object v5, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v5, :cond_6

    invoke-interface {v5}, La/b/p/c0;->d()V

    :cond_6
    iget-object v5, p1, La/b/k/h$k;->g:Landroid/view/View;

    if-nez v5, :cond_18

    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    const/4 v6, 0x0

    if-eqz v5, :cond_7

    iget-boolean v5, p1, La/b/k/h$k;->p:Z

    if-eqz v5, :cond_12

    :cond_7
    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    if-nez v5, :cond_d

    .line 1
    iget-object v5, p0, La/b/k/h;->e:Landroid/content/Context;

    iget v7, p1, La/b/k/h$k;->a:I

    if-eqz v7, :cond_8

    if-ne v7, v4, :cond_c

    :cond_8
    iget-object v4, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v4, :cond_c

    new-instance v4, Landroid/util/TypedValue;

    invoke-direct {v4}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v5}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v7

    sget v8, La/b/a;->actionBarTheme:I

    invoke-virtual {v7, v8, v4, v2}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v8, v4, Landroid/util/TypedValue;->resourceId:I

    if-eqz v8, :cond_9

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v8

    invoke-virtual {v8}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    move-result-object v8

    invoke-virtual {v8, v7}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    iget v9, v4, Landroid/util/TypedValue;->resourceId:I

    invoke-virtual {v8, v9, v2}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    sget v9, La/b/a;->actionBarWidgetTheme:I

    invoke-virtual {v8, v9, v4, v2}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    goto :goto_2

    :cond_9
    sget v8, La/b/a;->actionBarWidgetTheme:I

    invoke-virtual {v7, v8, v4, v2}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    move-object v8, v6

    :goto_2
    iget v9, v4, Landroid/util/TypedValue;->resourceId:I

    if-eqz v9, :cond_b

    if-nez v8, :cond_a

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v8

    invoke-virtual {v8}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    move-result-object v8

    invoke-virtual {v8, v7}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    :cond_a
    iget v4, v4, Landroid/util/TypedValue;->resourceId:I

    invoke-virtual {v8, v4, v2}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    :cond_b
    if-eqz v8, :cond_c

    new-instance v4, La/b/o/c;

    invoke-direct {v4, v5, v1}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v4}, La/b/o/c;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v5

    invoke-virtual {v5, v8}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    move-object v5, v4

    :cond_c
    new-instance v4, La/b/o/i/g;

    invoke-direct {v4, v5}, La/b/o/i/g;-><init>(Landroid/content/Context;)V

    .line 2
    iput-object p0, v4, La/b/o/i/g;->e:La/b/o/i/g$a;

    .line 3
    invoke-virtual {p1, v4}, La/b/k/h$k;->a(La/b/o/i/g;)V

    .line 4
    iget-object v4, p1, La/b/k/h$k;->h:La/b/o/i/g;

    if-nez v4, :cond_d

    return v1

    :cond_d
    if-eqz v3, :cond_f

    iget-object v4, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v4, :cond_f

    iget-object v4, p0, La/b/k/h;->m:La/b/k/h$c;

    if-nez v4, :cond_e

    new-instance v4, La/b/k/h$c;

    invoke-direct {v4, p0}, La/b/k/h$c;-><init>(La/b/k/h;)V

    iput-object v4, p0, La/b/k/h;->m:La/b/k/h$c;

    :cond_e
    iget-object v4, p0, La/b/k/h;->l:La/b/p/c0;

    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    iget-object v7, p0, La/b/k/h;->m:La/b/k/h$c;

    invoke-interface {v4, v5, v7}, La/b/p/c0;->b(Landroid/view/Menu;La/b/o/i/m$a;)V

    :cond_f
    iget-object v4, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v4}, La/b/o/i/g;->z()V

    iget v4, p1, La/b/k/h$k;->a:I

    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-interface {v0, v4, v5}, Landroid/view/Window$Callback;->onCreatePanelMenu(ILandroid/view/Menu;)Z

    move-result v4

    if-nez v4, :cond_11

    invoke-virtual {p1, v6}, La/b/k/h$k;->a(La/b/o/i/g;)V

    if-eqz v3, :cond_10

    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz p1, :cond_10

    iget-object p2, p0, La/b/k/h;->m:La/b/k/h$c;

    invoke-interface {p1, v6, p2}, La/b/p/c0;->b(Landroid/view/Menu;La/b/o/i/m$a;)V

    :cond_10
    return v1

    :cond_11
    iput-boolean v1, p1, La/b/k/h$k;->p:Z

    :cond_12
    iget-object v4, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v4}, La/b/o/i/g;->z()V

    iget-object v4, p1, La/b/k/h$k;->q:Landroid/os/Bundle;

    if-eqz v4, :cond_13

    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v5, v4}, La/b/o/i/g;->v(Landroid/os/Bundle;)V

    iput-object v6, p1, La/b/k/h$k;->q:Landroid/os/Bundle;

    :cond_13
    iget-object v4, p1, La/b/k/h$k;->g:Landroid/view/View;

    iget-object v5, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-interface {v0, v1, v4, v5}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    move-result v0

    if-nez v0, :cond_15

    if-eqz v3, :cond_14

    iget-object p2, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz p2, :cond_14

    iget-object v0, p0, La/b/k/h;->m:La/b/k/h$c;

    invoke-interface {p2, v6, v0}, La/b/p/c0;->b(Landroid/view/Menu;La/b/o/i/m$a;)V

    :cond_14
    iget-object p1, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {p1}, La/b/o/i/g;->y()V

    return v1

    :cond_15
    if-eqz p2, :cond_16

    invoke-virtual {p2}, Landroid/view/KeyEvent;->getDeviceId()I

    move-result p2

    goto :goto_3

    :cond_16
    const/4 p2, -0x1

    :goto_3
    invoke-static {p2}, Landroid/view/KeyCharacterMap;->load(I)Landroid/view/KeyCharacterMap;

    move-result-object p2

    invoke-virtual {p2}, Landroid/view/KeyCharacterMap;->getKeyboardType()I

    move-result p2

    if-eq p2, v2, :cond_17

    move p2, v2

    goto :goto_4

    :cond_17
    move p2, v1

    :goto_4
    iput-boolean p2, p1, La/b/k/h$k;->n:Z

    iget-object v0, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v0, p2}, La/b/o/i/g;->setQwertyMode(Z)V

    iget-object p2, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {p2}, La/b/o/i/g;->y()V

    :cond_18
    iput-boolean v2, p1, La/b/k/h$k;->k:Z

    iput-boolean v1, p1, La/b/k/h$k;->l:Z

    iput-object p1, p0, La/b/k/h;->H:La/b/k/h$k;

    return v2
.end method

.method public final L()Z
    .locals 1

    iget-boolean v0, p0, La/b/k/h;->u:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    if-eqz v0, :cond_0

    invoke-static {v0}, La/f/j/k;->m(Landroid/view/View;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public final M()V
    .locals 2

    iget-boolean v0, p0, La/b/k/h;->u:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Landroid/util/AndroidRuntimeException;

    const-string v1, "Window feature must be requested before adding content"

    invoke-direct {v0, v1}, Landroid/util/AndroidRuntimeException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final N(La/f/j/t;Landroid/graphics/Rect;)I
    .locals 10

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, La/f/j/t;->d()I

    move-result v1

    goto :goto_0

    :cond_0
    if-eqz p2, :cond_1

    iget v1, p2, Landroid/graphics/Rect;->top:I

    goto :goto_0

    :cond_1
    move v1, v0

    :goto_0
    iget-object v2, p0, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    const/16 v3, 0x8

    if-eqz v2, :cond_10

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v2

    instance-of v2, v2, Landroid/view/ViewGroup$MarginLayoutParams;

    if-eqz v2, :cond_10

    iget-object v2, p0, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v2}, Landroid/view/ViewGroup;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v2

    check-cast v2, Landroid/view/ViewGroup$MarginLayoutParams;

    iget-object v4, p0, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v4}, Landroid/view/ViewGroup;->isShown()Z

    move-result v4

    const/4 v5, 0x1

    if-eqz v4, :cond_e

    iget-object v4, p0, La/b/k/h;->X:Landroid/graphics/Rect;

    if-nez v4, :cond_2

    new-instance v4, Landroid/graphics/Rect;

    invoke-direct {v4}, Landroid/graphics/Rect;-><init>()V

    iput-object v4, p0, La/b/k/h;->X:Landroid/graphics/Rect;

    new-instance v4, Landroid/graphics/Rect;

    invoke-direct {v4}, Landroid/graphics/Rect;-><init>()V

    iput-object v4, p0, La/b/k/h;->Y:Landroid/graphics/Rect;

    :cond_2
    iget-object v4, p0, La/b/k/h;->X:Landroid/graphics/Rect;

    iget-object v6, p0, La/b/k/h;->Y:Landroid/graphics/Rect;

    if-nez p1, :cond_3

    invoke-virtual {v4, p2}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    goto :goto_1

    :cond_3
    invoke-virtual {p1}, La/f/j/t;->b()I

    move-result p2

    invoke-virtual {p1}, La/f/j/t;->d()I

    move-result v7

    invoke-virtual {p1}, La/f/j/t;->c()I

    move-result v8

    invoke-virtual {p1}, La/f/j/t;->a()I

    move-result p1

    invoke-virtual {v4, p2, v7, v8, p1}, Landroid/graphics/Rect;->set(IIII)V

    :goto_1
    iget-object p1, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-static {p1, v4, v6}, La/b/p/d1;->a(Landroid/view/View;Landroid/graphics/Rect;Landroid/graphics/Rect;)V

    iget p1, v4, Landroid/graphics/Rect;->top:I

    iget p2, v4, Landroid/graphics/Rect;->left:I

    iget v4, v4, Landroid/graphics/Rect;->right:I

    iget-object v6, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-static {v6}, La/f/j/k;->h(Landroid/view/View;)La/f/j/t;

    move-result-object v6

    invoke-virtual {v6}, La/f/j/t;->b()I

    move-result v7

    invoke-virtual {v6}, La/f/j/t;->c()I

    move-result v6

    iget v8, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-ne v8, p1, :cond_5

    iget v8, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    if-ne v8, p2, :cond_5

    iget v8, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    if-eq v8, v4, :cond_4

    goto :goto_2

    :cond_4
    move p2, v0

    goto :goto_3

    :cond_5
    :goto_2
    iput p1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iput p2, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v4, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    move p2, v5

    :goto_3
    if-lez p1, :cond_6

    iget-object p1, p0, La/b/k/h;->x:Landroid/view/View;

    if-nez p1, :cond_6

    new-instance p1, Landroid/view/View;

    iget-object v4, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-direct {p1, v4}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    iput-object p1, p0, La/b/k/h;->x:Landroid/view/View;

    invoke-virtual {p1, v3}, Landroid/view/View;->setVisibility(I)V

    new-instance p1, Landroid/widget/FrameLayout$LayoutParams;

    iget v4, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    const/16 v8, 0x33

    const/4 v9, -0x1

    invoke-direct {p1, v9, v4, v8}, Landroid/widget/FrameLayout$LayoutParams;-><init>(III)V

    iput v7, p1, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I

    iput v6, p1, Landroid/widget/FrameLayout$LayoutParams;->rightMargin:I

    iget-object v4, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    iget-object v6, p0, La/b/k/h;->x:Landroid/view/View;

    invoke-virtual {v4, v6, v9, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    goto :goto_4

    :cond_6
    iget-object p1, p0, La/b/k/h;->x:Landroid/view/View;

    if-eqz p1, :cond_8

    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p1

    check-cast p1, Landroid/view/ViewGroup$MarginLayoutParams;

    iget v4, p1, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iget v8, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-ne v4, v8, :cond_7

    iget v4, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    if-ne v4, v7, :cond_7

    iget v4, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    if-eq v4, v6, :cond_8

    :cond_7
    iget v4, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iput v4, p1, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iput v7, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v6, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iget-object v4, p0, La/b/k/h;->x:Landroid/view/View;

    invoke-virtual {v4, p1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_8
    :goto_4
    iget-object p1, p0, La/b/k/h;->x:Landroid/view/View;

    if-eqz p1, :cond_9

    move p1, v5

    goto :goto_5

    :cond_9
    move p1, v0

    :goto_5
    if-eqz p1, :cond_c

    iget-object v4, p0, La/b/k/h;->x:Landroid/view/View;

    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    move-result v4

    if-eqz v4, :cond_c

    iget-object v4, p0, La/b/k/h;->x:Landroid/view/View;

    .line 1
    invoke-static {v4}, La/f/j/k;->j(Landroid/view/View;)I

    move-result v6

    and-int/lit16 v6, v6, 0x2000

    if-eqz v6, :cond_a

    goto :goto_6

    :cond_a
    move v5, v0

    :goto_6
    if-eqz v5, :cond_b

    iget-object v5, p0, La/b/k/h;->e:Landroid/content/Context;

    sget v6, La/b/c;->abc_decor_view_status_guard_light:I

    goto :goto_7

    :cond_b
    iget-object v5, p0, La/b/k/h;->e:Landroid/content/Context;

    sget v6, La/b/c;->abc_decor_view_status_guard:I

    :goto_7
    invoke-static {v5, v6}, La/f/d/a;->a(Landroid/content/Context;I)I

    move-result v5

    invoke-virtual {v4, v5}, Landroid/view/View;->setBackgroundColor(I)V

    .line 2
    :cond_c
    iget-boolean v4, p0, La/b/k/h;->C:Z

    if-nez v4, :cond_d

    if-eqz p1, :cond_d

    move v1, v0

    :cond_d
    move v5, p2

    goto :goto_8

    :cond_e
    iget p1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-eqz p1, :cond_f

    iput v0, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    move p1, v0

    goto :goto_8

    :cond_f
    move p1, v0

    move v5, p1

    :goto_8
    if-eqz v5, :cond_11

    iget-object p2, p0, La/b/k/h;->p:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    goto :goto_9

    :cond_10
    move p1, v0

    :cond_11
    :goto_9
    iget-object p2, p0, La/b/k/h;->x:Landroid/view/View;

    if-eqz p2, :cond_13

    if-eqz p1, :cond_12

    goto :goto_a

    :cond_12
    move v0, v3

    :goto_a
    invoke-virtual {p2, v0}, Landroid/view/View;->setVisibility(I)V

    :cond_13
    return v1
.end method

.method public a(La/b/o/i/g;)V
    .locals 5

    .line 1
    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    const/4 v0, 0x1

    const/4 v1, 0x0

    if-eqz p1, :cond_3

    invoke-interface {p1}, La/b/p/c0;->f()Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/ViewConfiguration;->hasPermanentMenuKey()Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {p1}, La/b/p/c0;->c()Z

    move-result p1

    if-eqz p1, :cond_3

    :cond_0
    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object p1

    iget-object v2, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {v2}, La/b/p/c0;->e()Z

    move-result v2

    const/16 v3, 0x6c

    if-eqz v2, :cond_1

    iget-object v0, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {v0}, La/b/p/c0;->g()Z

    iget-boolean v0, p0, La/b/k/h;->M:Z

    if-nez v0, :cond_4

    invoke-virtual {p0, v1}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-object v0, v0, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-interface {p1, v3, v0}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    goto :goto_0

    :cond_1
    if-eqz p1, :cond_4

    iget-boolean v2, p0, La/b/k/h;->M:Z

    if-nez v2, :cond_4

    iget-boolean v2, p0, La/b/k/h;->T:Z

    if-eqz v2, :cond_2

    iget v2, p0, La/b/k/h;->U:I

    and-int/2addr v0, v2

    if-eqz v0, :cond_2

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    iget-object v2, p0, La/b/k/h;->V:Ljava/lang/Runnable;

    invoke-virtual {v0, v2}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    iget-object v0, p0, La/b/k/h;->V:Ljava/lang/Runnable;

    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    :cond_2
    invoke-virtual {p0, v1}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-object v2, v0, La/b/k/h$k;->h:La/b/o/i/g;

    if-eqz v2, :cond_4

    iget-boolean v4, v0, La/b/k/h$k;->p:Z

    if-nez v4, :cond_4

    iget-object v4, v0, La/b/k/h$k;->g:Landroid/view/View;

    invoke-interface {p1, v1, v4, v2}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    move-result v1

    if-eqz v1, :cond_4

    iget-object v0, v0, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-interface {p1, v3, v0}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {p1}, La/b/p/c0;->a()Z

    goto :goto_0

    :cond_3
    invoke-virtual {p0, v1}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object p1

    iput-boolean v0, p1, La/b/k/h$k;->o:Z

    invoke-virtual {p0, p1, v1}, La/b/k/h;->u(La/b/k/h$k;Z)V

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, La/b/k/h;->I(La/b/k/h$k;Landroid/view/KeyEvent;)V

    :cond_4
    :goto_0
    return-void
.end method

.method public b(La/b/o/i/g;Landroid/view/MenuItem;)Z
    .locals 2

    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-boolean v1, p0, La/b/k/h;->M:Z

    if-nez v1, :cond_0

    invoke-virtual {p1}, La/b/o/i/g;->k()La/b/o/i/g;

    move-result-object p1

    invoke-virtual {p0, p1}, La/b/k/h;->B(Landroid/view/Menu;)La/b/k/h$k;

    move-result-object p1

    if-eqz p1, :cond_0

    iget p1, p1, La/b/k/h$k;->a:I

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public c(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    invoke-virtual {p0}, La/b/k/h;->z()V

    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    const v1, 0x1020002

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iget-object p1, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 1
    iget-object p1, p1, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 2
    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V

    return-void
.end method

.method public f()V
    .locals 2

    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/LayoutInflater;->getFactory()Landroid/view/LayoutInflater$Factory;

    move-result-object v1

    if-nez v1, :cond_0

    .line 1
    invoke-virtual {v0, p0}, Landroid/view/LayoutInflater;->setFactory2(Landroid/view/LayoutInflater$Factory2;)V

    goto :goto_0

    .line 2
    :cond_0
    invoke-virtual {v0}, Landroid/view/LayoutInflater;->getFactory2()Landroid/view/LayoutInflater$Factory2;

    move-result-object v0

    instance-of v0, v0, La/b/k/h;

    if-nez v0, :cond_1

    const-string v0, "AppCompatDelegate"

    const-string v1, "The Activity\'s LayoutInflater already has a Factory installed so we can not install AppCompat\'s"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_1
    :goto_0
    return-void
.end method

.method public g()V
    .locals 1

    .line 1
    invoke-virtual {p0}, La/b/k/h;->F()V

    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, La/b/k/h;->G(I)V

    return-void
.end method

.method public h(Landroid/os/Bundle;)V
    .locals 3

    const/4 p1, 0x1

    iput-boolean p1, p0, La/b/k/h;->J:Z

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, La/b/k/h;->q(Z)Z

    invoke-virtual {p0}, La/b/k/h;->A()V

    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_2

    const/4 v1, 0x0

    :try_start_0
    check-cast v0, Landroid/app/Activity;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 1
    :try_start_1
    invoke-virtual {v0}, Landroid/app/Activity;->getComponentName()Landroid/content/ComponentName;

    move-result-object v2

    invoke-static {v0, v2}, La/b/k/h$i;->m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    move-result-object v1
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_0

    :catch_0
    move-exception v0

    :try_start_2
    new-instance v2, Ljava/lang/IllegalArgumentException;

    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw v2
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_1

    :catch_1
    :goto_0
    if-eqz v1, :cond_1

    .line 2
    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    if-nez v0, :cond_0

    .line 3
    iput-boolean p1, p0, La/b/k/h;->W:Z

    goto :goto_1

    :cond_0
    invoke-virtual {v0, p1}, La/b/k/a;->g(Z)V

    .line 4
    :cond_1
    :goto_1
    sget-object v0, La/b/k/g;->c:Ljava/lang/Object;

    monitor-enter v0

    :try_start_3
    invoke-static {p0}, La/b/k/g;->j(La/b/k/g;)V

    sget-object v1, La/b/k/g;->b:La/d/c;

    new-instance v2, Ljava/lang/ref/WeakReference;

    invoke-direct {v2, p0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v1, v2}, La/d/c;->add(Ljava/lang/Object;)Z

    monitor-exit v0

    goto :goto_2

    :catchall_0
    move-exception p1

    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1

    .line 5
    :cond_2
    :goto_2
    iput-boolean p1, p0, La/b/k/h;->K:Z

    return-void
.end method

.method public i()V
    .locals 3

    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v0, v0, Landroid/app/Activity;

    if-eqz v0, :cond_0

    .line 1
    sget-object v0, La/b/k/g;->c:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    invoke-static {p0}, La/b/k/g;->j(La/b/k/g;)V

    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception v1

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1

    .line 2
    :cond_0
    :goto_0
    iget-boolean v0, p0, La/b/k/h;->T:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, La/b/k/h;->V:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    :cond_1
    const/4 v0, 0x0

    iput-boolean v0, p0, La/b/k/h;->L:Z

    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/k/h;->M:Z

    iget v0, p0, La/b/k/h;->N:I

    const/16 v1, -0x64

    if-eq v0, v1, :cond_2

    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_2

    check-cast v0, Landroid/app/Activity;

    invoke-virtual {v0}, Landroid/app/Activity;->isChangingConfigurations()Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, La/b/k/h;->a0:La/d/h;

    iget-object v1, p0, La/b/k/h;->d:Ljava/lang/Object;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    iget v2, p0, La/b/k/h;->N:I

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, La/d/h;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_2
    sget-object v0, La/b/k/h;->a0:La/d/h;

    iget-object v1, p0, La/b/k/h;->d:Ljava/lang/Object;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, La/d/h;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_4

    if-eqz v0, :cond_3

    goto :goto_2

    :cond_3
    const/4 v0, 0x0

    .line 3
    throw v0

    .line 4
    :cond_4
    :goto_2
    iget-object v0, p0, La/b/k/h;->R:La/b/k/h$g;

    if-eqz v0, :cond_5

    invoke-virtual {v0}, La/b/k/h$g;->a()V

    :cond_5
    iget-object v0, p0, La/b/k/h;->S:La/b/k/h$g;

    if-eqz v0, :cond_6

    invoke-virtual {v0}, La/b/k/h$g;->a()V

    :cond_6
    return-void
.end method

.method public k(I)Z
    .locals 5

    const-string v0, "AppCompatDelegate"

    const/16 v1, 0x8

    const/16 v2, 0x6d

    const/16 v3, 0x6c

    if-ne p1, v1, :cond_0

    const-string p1, "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature."

    .line 1
    invoke-static {v0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    move p1, v3

    goto :goto_0

    :cond_0
    const/16 v1, 0x9

    if-ne p1, v1, :cond_1

    const-string p1, "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature."

    invoke-static {v0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    move p1, v2

    .line 2
    :cond_1
    :goto_0
    iget-boolean v0, p0, La/b/k/h;->E:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    if-ne p1, v3, :cond_2

    return v1

    :cond_2
    iget-boolean v0, p0, La/b/k/h;->A:Z

    const/4 v4, 0x1

    if-eqz v0, :cond_3

    if-ne p1, v4, :cond_3

    iput-boolean v1, p0, La/b/k/h;->A:Z

    :cond_3
    if-eq p1, v4, :cond_9

    const/4 v0, 0x2

    if-eq p1, v0, :cond_8

    const/4 v0, 0x5

    if-eq p1, v0, :cond_7

    const/16 v0, 0xa

    if-eq p1, v0, :cond_6

    if-eq p1, v3, :cond_5

    if-eq p1, v2, :cond_4

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0, p1}, Landroid/view/Window;->requestFeature(I)Z

    move-result p1

    return p1

    :cond_4
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->B:Z

    return v4

    :cond_5
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->A:Z

    return v4

    :cond_6
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->C:Z

    return v4

    :cond_7
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->z:Z

    return v4

    :cond_8
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->y:Z

    return v4

    :cond_9
    invoke-virtual {p0}, La/b/k/h;->M()V

    iput-boolean v4, p0, La/b/k/h;->E:Z

    return v4
.end method

.method public l(I)V
    .locals 2

    invoke-virtual {p0}, La/b/k/h;->z()V

    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    const v1, 0x1020002

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    iget-object v1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v1

    invoke-virtual {v1, p1, v0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    iget-object p1, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 1
    iget-object p1, p1, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 2
    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V

    return-void
.end method

.method public m(Landroid/view/View;)V
    .locals 2

    invoke-virtual {p0}, La/b/k/h;->z()V

    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    const v1, 0x1020002

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    iget-object p1, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 1
    iget-object p1, p1, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 2
    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V

    return-void
.end method

.method public n(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    invoke-virtual {p0}, La/b/k/h;->z()V

    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    const v1, 0x1020002

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iget-object p1, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 1
    iget-object p1, p1, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 2
    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V

    return-void
.end method

.method public final o(Ljava/lang/CharSequence;)V
    .locals 1

    iput-object p1, p0, La/b/k/h;->k:Ljava/lang/CharSequence;

    iget-object v0, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, La/b/p/c0;->setWindowTitle(Ljava/lang/CharSequence;)V

    goto :goto_0

    .line 1
    :cond_0
    iget-object v0, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_1

    .line 2
    invoke-virtual {v0, p1}, La/b/k/a;->i(Ljava/lang/CharSequence;)V

    goto :goto_0

    :cond_1
    iget-object v0, p0, La/b/k/h;->w:Landroid/widget/TextView;

    if-eqz v0, :cond_2

    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_2
    :goto_0
    return-void
.end method

.method public final onCreateView(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;
    .locals 7

    .line 1
    iget-object p1, p0, La/b/k/h;->Z:La/b/k/o;

    const/4 v0, 0x0

    if-nez p1, :cond_1

    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    sget-object v1, La/b/j;->AppCompatTheme:[I

    invoke-virtual {p1, v1}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object p1

    sget v1, La/b/j;->AppCompatTheme_viewInflaterClass:I

    invoke-virtual {p1, v1}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object p1

    if-nez p1, :cond_0

    new-instance p1, La/b/k/o;

    invoke-direct {p1}, La/b/k/o;-><init>()V

    goto :goto_0

    :cond_0
    :try_start_0
    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v1

    new-array v2, v0, [Ljava/lang/Class;

    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v1

    new-array v2, v0, [Ljava/lang/Object;

    invoke-virtual {v1, v2}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/b/k/o;

    iput-object v1, p0, La/b/k/h;->Z:La/b/k/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Failed to instantiate custom view inflater "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, ". Falling back to default."

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string v2, "AppCompatDelegate"

    invoke-static {v2, p1, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    new-instance p1, La/b/k/o;

    invoke-direct {p1}, La/b/k/o;-><init>()V

    :goto_0
    iput-object p1, p0, La/b/k/h;->Z:La/b/k/o;

    :cond_1
    :goto_1
    iget-object p1, p0, La/b/k/h;->Z:La/b/k/o;

    invoke-static {}, La/b/p/c1;->a()Z

    const/4 v1, 0x0

    if-eqz p1, :cond_e

    .line 2
    sget-object v2, La/b/j;->View:[I

    invoke-virtual {p3, p4, v2, v0, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v2

    sget v3, La/b/j;->View_theme:I

    invoke-virtual {v2, v3, v0}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v3

    if-eqz v3, :cond_2

    const-string v4, "AppCompatViewInflater"

    const-string v5, "app:theme is now deprecated. Please move to using android:theme instead."

    invoke-static {v4, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_2
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    if-eqz v3, :cond_4

    instance-of v2, p3, La/b/o/c;

    if-eqz v2, :cond_3

    move-object v2, p3

    check-cast v2, La/b/o/c;

    .line 3
    iget v2, v2, La/b/o/c;->a:I

    if-eq v2, v3, :cond_4

    .line 4
    :cond_3
    new-instance v2, La/b/o/c;

    invoke-direct {v2, p3, v3}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    goto :goto_2

    :cond_4
    move-object v2, p3

    .line 5
    :goto_2
    invoke-virtual {p2}, Ljava/lang/String;->hashCode()I

    move-result v3

    const/4 v4, -0x1

    const/4 v5, 0x1

    sparse-switch v3, :sswitch_data_0

    goto/16 :goto_3

    :sswitch_0
    const-string v3, "Button"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x2

    goto/16 :goto_4

    :sswitch_1
    const-string v3, "EditText"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x3

    goto/16 :goto_4

    :sswitch_2
    const-string v3, "CheckBox"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x6

    goto/16 :goto_4

    :sswitch_3
    const-string v3, "AutoCompleteTextView"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0x9

    goto/16 :goto_4

    :sswitch_4
    const-string v3, "ImageView"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    move v3, v5

    goto/16 :goto_4

    :sswitch_5
    const-string v3, "ToggleButton"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0xd

    goto :goto_4

    :sswitch_6
    const-string v3, "RadioButton"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x7

    goto :goto_4

    :sswitch_7
    const-string v3, "Spinner"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x4

    goto :goto_4

    :sswitch_8
    const-string v3, "SeekBar"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0xc

    goto :goto_4

    :sswitch_9
    const-string v3, "ImageButton"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 v3, 0x5

    goto :goto_4

    :sswitch_a
    const-string v3, "TextView"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    move v3, v0

    goto :goto_4

    :sswitch_b
    const-string v3, "MultiAutoCompleteTextView"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0xa

    goto :goto_4

    :sswitch_c
    const-string v3, "CheckedTextView"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0x8

    goto :goto_4

    :sswitch_d
    const-string v3, "RatingBar"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0xb

    goto :goto_4

    :cond_5
    :goto_3
    move v3, v4

    :goto_4
    packed-switch v3, :pswitch_data_0

    goto :goto_6

    .line 6
    :pswitch_0
    new-instance v3, La/b/p/b0;

    invoke-direct {v3, v2, p4}, La/b/p/b0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 7
    :pswitch_1
    new-instance v3, La/b/p/t;

    invoke-direct {v3, v2, p4}, La/b/p/t;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 8
    :pswitch_2
    new-instance v3, La/b/p/s;

    invoke-direct {v3, v2, p4}, La/b/p/s;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 9
    :pswitch_3
    new-instance v3, La/b/p/o;

    invoke-direct {v3, v2, p4}, La/b/p/o;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 10
    :pswitch_4
    new-instance v3, La/b/p/d;

    invoke-direct {v3, v2, p4}, La/b/p/d;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 11
    :pswitch_5
    new-instance v3, La/b/p/h;

    invoke-direct {v3, v2, p4}, La/b/p/h;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 12
    :pswitch_6
    new-instance v3, La/b/p/r;

    invoke-direct {v3, v2, p4}, La/b/p/r;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 13
    :pswitch_7
    new-instance v3, La/b/p/g;

    invoke-direct {v3, v2, p4}, La/b/p/g;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 14
    :pswitch_8
    new-instance v3, La/b/p/l;

    .line 15
    sget v6, La/b/a;->imageButtonStyle:I

    invoke-direct {v3, v2, p4, v6}, La/b/p/l;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    goto :goto_5

    .line 16
    :pswitch_9
    new-instance v3, La/b/p/w;

    .line 17
    sget v6, La/b/a;->spinnerStyle:I

    invoke-direct {v3, v2, p4, v6}, La/b/p/w;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    goto :goto_5

    .line 18
    :pswitch_a
    new-instance v3, La/b/p/k;

    invoke-direct {v3, v2, p4}, La/b/p/k;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 19
    :pswitch_b
    new-instance v3, La/b/p/f;

    invoke-direct {v3, v2, p4}, La/b/p/f;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_5

    .line 20
    :pswitch_c
    new-instance v3, La/b/p/n;

    .line 21
    invoke-direct {v3, v2, p4, v0}, La/b/p/n;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    goto :goto_5

    .line 22
    :pswitch_d
    new-instance v3, La/b/p/z;

    invoke-direct {v3, v2, p4}, La/b/p/z;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 23
    :goto_5
    invoke-virtual {p1, v3, p2}, La/b/k/o;->b(Landroid/view/View;Ljava/lang/String;)V

    goto :goto_7

    :goto_6
    move-object v3, v1

    :goto_7
    if-nez v3, :cond_a

    if-eq p3, v2, :cond_a

    const-string p3, "view"

    .line 24
    invoke-virtual {p2, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_6

    const-string p2, "class"

    invoke-interface {p4, v1, p2}, Landroid/util/AttributeSet;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    :cond_6
    :try_start_1
    iget-object p3, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v2, p3, v0

    iget-object p3, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object p4, p3, v5

    const/16 p3, 0x2e

    invoke-virtual {p2, p3}, Ljava/lang/String;->indexOf(I)I

    move-result p3

    if-ne v4, p3, :cond_9

    move p3, v0

    :goto_8
    sget-object v3, La/b/k/o;->d:[Ljava/lang/String;

    array-length v3, v3

    if-ge p3, v3, :cond_8

    sget-object v3, La/b/k/o;->d:[Ljava/lang/String;

    aget-object v3, v3, p3

    invoke-virtual {p1, v2, p2, v3}, La/b/k/o;->a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/view/View;

    move-result-object v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v3, :cond_7

    iget-object p1, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v1, p1, v0

    aput-object v1, p1, v5

    move-object v1, v3

    goto :goto_9

    :cond_7
    add-int/lit8 p3, p3, 0x1

    goto :goto_8

    :cond_8
    iget-object p1, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v1, p1, v0

    aput-object v1, p1, v5

    goto :goto_9

    :cond_9
    :try_start_2
    invoke-virtual {p1, v2, p2, v1}, La/b/k/o;->a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/view/View;

    move-result-object p2
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    iget-object p1, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v1, p1, v0

    aput-object v1, p1, v5

    move-object v1, p2

    goto :goto_9

    :catchall_1
    move-exception p2

    iget-object p1, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v1, p1, v0

    aput-object v1, p1, v5

    throw p2

    :catch_0
    iget-object p1, p1, La/b/k/o;->a:[Ljava/lang/Object;

    aput-object v1, p1, v0

    aput-object v1, p1, v5

    :goto_9
    move-object v3, v1

    :cond_a
    if-eqz v3, :cond_d

    .line 25
    invoke-virtual {v3}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    instance-of p2, p1, Landroid/content/ContextWrapper;

    if-eqz p2, :cond_d

    invoke-static {v3}, La/f/j/k;->k(Landroid/view/View;)Z

    move-result p2

    if-nez p2, :cond_b

    goto :goto_a

    :cond_b
    sget-object p2, La/b/k/o;->c:[I

    invoke-virtual {p1, p4, p2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p1

    invoke-virtual {p1, v0}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_c

    new-instance p3, La/b/k/o$a;

    invoke-direct {p3, v3, p2}, La/b/k/o$a;-><init>(Landroid/view/View;Ljava/lang/String;)V

    invoke-virtual {v3, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    :cond_c
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    :cond_d
    :goto_a
    return-object v3

    .line 26
    :cond_e
    throw v1

    nop

    :sswitch_data_0
    .sparse-switch
        -0x7404ceea -> :sswitch_d
        -0x56c015e7 -> :sswitch_c
        -0x503aa7ad -> :sswitch_b
        -0x37f7066e -> :sswitch_a
        -0x37e04bb3 -> :sswitch_9
        -0x274065a5 -> :sswitch_8
        -0x1440b607 -> :sswitch_7
        0x2e46a6ed -> :sswitch_6
        0x2fa453c6 -> :sswitch_5
        0x431b5280 -> :sswitch_4
        0x5445f9ba -> :sswitch_3
        0x5f7507c3 -> :sswitch_2
        0x63577677 -> :sswitch_1
        0x77471352 -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public onCreateView(Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0, p1, p2, p3}, La/b/k/h;->onCreateView(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public p()Z
    .locals 1

    const/4 v0, 0x1

    invoke-virtual {p0, v0}, La/b/k/h;->q(Z)Z

    move-result v0

    return v0
.end method

.method public final q(Z)Z
    .locals 10

    iget-boolean v0, p0, La/b/k/h;->M:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    .line 1
    :cond_0
    iget v0, p0, La/b/k/h;->N:I

    const/16 v2, -0x64

    if-eq v0, v2, :cond_1

    goto :goto_0

    :cond_1
    move v0, v2

    .line 2
    :goto_0
    iget-object v2, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {p0, v2, v0}, La/b/k/h;->H(Landroid/content/Context;I)I

    move-result v2

    .line 3
    iget-object v3, p0, La/b/k/h;->e:Landroid/content/Context;

    const/4 v4, 0x0

    invoke-virtual {p0, v3, v2, v4}, La/b/k/h;->v(Landroid/content/Context;ILandroid/content/res/Configuration;)Landroid/content/res/Configuration;

    move-result-object v2

    .line 4
    iget-boolean v3, p0, La/b/k/h;->Q:Z

    const/4 v5, 0x1

    if-nez v3, :cond_5

    iget-object v3, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v3, v3, Landroid/app/Activity;

    if-eqz v3, :cond_5

    iget-object v3, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {v3}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v3

    if-nez v3, :cond_2

    move v3, v1

    goto :goto_4

    :cond_2
    :try_start_0
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v7, 0x1d

    if-lt v6, v7, :cond_3

    const/high16 v6, 0x100c0000

    goto :goto_1

    :cond_3
    const/high16 v6, 0xc0000

    :goto_1
    new-instance v7, Landroid/content/ComponentName;

    iget-object v8, p0, La/b/k/h;->e:Landroid/content/Context;

    iget-object v9, p0, La/b/k/h;->d:Ljava/lang/Object;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v9

    invoke-direct {v7, v8, v9}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {v3, v7, v6}, Landroid/content/pm/PackageManager;->getActivityInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;

    move-result-object v3

    if-eqz v3, :cond_4

    iget v3, v3, Landroid/content/pm/ActivityInfo;->configChanges:I

    and-int/lit16 v3, v3, 0x200

    if-eqz v3, :cond_4

    move v3, v5

    goto :goto_2

    :cond_4
    move v3, v1

    :goto_2
    iput-boolean v3, p0, La/b/k/h;->P:Z
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    :catch_0
    move-exception v3

    const-string v6, "AppCompatDelegate"

    const-string v7, "Exception while getting ActivityInfo"

    invoke-static {v6, v7, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    iput-boolean v1, p0, La/b/k/h;->P:Z

    :cond_5
    :goto_3
    iput-boolean v5, p0, La/b/k/h;->Q:Z

    iget-boolean v3, p0, La/b/k/h;->P:Z

    .line 5
    :goto_4
    iget-object v6, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    invoke-virtual {v6}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v6

    iget v6, v6, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v6, v6, 0x30

    iget v2, v2, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v2, v2, 0x30

    if-eq v6, v2, :cond_7

    if-eqz p1, :cond_7

    if-nez v3, :cond_7

    iget-boolean p1, p0, La/b/k/h;->J:Z

    if-eqz p1, :cond_7

    sget-boolean p1, La/b/k/h;->d0:Z

    if-nez p1, :cond_6

    iget-boolean p1, p0, La/b/k/h;->K:Z

    if-eqz p1, :cond_7

    :cond_6
    iget-object p1, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v7, p1, Landroid/app/Activity;

    if-eqz v7, :cond_7

    check-cast p1, Landroid/app/Activity;

    invoke-virtual {p1}, Landroid/app/Activity;->isChild()Z

    move-result p1

    if-nez p1, :cond_7

    iget-object p1, p0, La/b/k/h;->d:Ljava/lang/Object;

    check-cast p1, Landroid/app/Activity;

    invoke-static {p1}, La/f/c/a;->f(Landroid/app/Activity;)V

    move p1, v5

    goto :goto_5

    :cond_7
    move p1, v1

    :goto_5
    if-nez p1, :cond_12

    if-eq v6, v2, :cond_12

    .line 6
    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    new-instance v6, Landroid/content/res/Configuration;

    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v7

    invoke-direct {v6, v7}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v7

    iget v7, v7, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v7, v7, -0x31

    or-int/2addr v2, v7

    iput v2, v6, Landroid/content/res/Configuration;->uiMode:I

    invoke-virtual {p1, v6, v4}, Landroid/content/res/Resources;->updateConfiguration(Landroid/content/res/Configuration;Landroid/util/DisplayMetrics;)V

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v7, 0x1a

    if-ge v2, v7, :cond_e

    const/16 v7, 0x1c

    if-lt v2, v7, :cond_8

    goto :goto_a

    .line 7
    :cond_8
    sget-boolean v2, La/b/k/h$i;->h:Z

    const-string v7, "ResourcesFlusher"

    if-nez v2, :cond_9

    :try_start_1
    const-class v2, Landroid/content/res/Resources;

    const-string v8, "mResourcesImpl"

    invoke-virtual {v2, v8}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v2

    sput-object v2, La/b/k/h$i;->g:Ljava/lang/reflect/Field;

    invoke-virtual {v2, v5}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    :try_end_1
    .catch Ljava/lang/NoSuchFieldException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_6

    :catch_1
    move-exception v2

    const-string v8, "Could not retrieve Resources#mResourcesImpl field"

    invoke-static {v7, v8, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_6
    sput-boolean v5, La/b/k/h$i;->h:Z

    :cond_9
    sget-object v2, La/b/k/h$i;->g:Ljava/lang/reflect/Field;

    if-nez v2, :cond_a

    goto :goto_a

    :cond_a
    :try_start_2
    invoke-virtual {v2, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_2 .. :try_end_2} :catch_2

    goto :goto_7

    :catch_2
    move-exception p1

    const-string v2, "Could not retrieve value from Resources#mResourcesImpl"

    invoke-static {v7, v2, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    move-object p1, v4

    :goto_7
    if-nez p1, :cond_b

    goto :goto_a

    :cond_b
    sget-boolean v2, La/b/k/h$i;->b:Z

    if-nez v2, :cond_c

    :try_start_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    const-string v8, "mDrawableCache"

    invoke-virtual {v2, v8}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v2

    sput-object v2, La/b/k/h$i;->a:Ljava/lang/reflect/Field;

    invoke-virtual {v2, v5}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    :try_end_3
    .catch Ljava/lang/NoSuchFieldException; {:try_start_3 .. :try_end_3} :catch_3

    goto :goto_8

    :catch_3
    move-exception v2

    const-string v8, "Could not retrieve ResourcesImpl#mDrawableCache field"

    invoke-static {v7, v8, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_8
    sput-boolean v5, La/b/k/h$i;->b:Z

    :cond_c
    sget-object v2, La/b/k/h$i;->a:Ljava/lang/reflect/Field;

    if-eqz v2, :cond_d

    :try_start_4
    invoke-virtual {v2, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4
    :try_end_4
    .catch Ljava/lang/IllegalAccessException; {:try_start_4 .. :try_end_4} :catch_4

    goto :goto_9

    :catch_4
    move-exception p1

    const-string v2, "Could not retrieve value from ResourcesImpl#mDrawableCache"

    invoke-static {v7, v2, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_d
    :goto_9
    if-eqz v4, :cond_e

    invoke-static {v4}, La/b/k/h$i;->j(Ljava/lang/Object;)V

    .line 8
    :cond_e
    :goto_a
    iget p1, p0, La/b/k/h;->O:I

    if-eqz p1, :cond_f

    iget-object v2, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {v2, p1}, Landroid/content/Context;->setTheme(I)V

    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p1

    iget v2, p0, La/b/k/h;->O:I

    invoke-virtual {p1, v2, v5}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    :cond_f
    if-eqz v3, :cond_13

    iget-object p1, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v2, p1, Landroid/app/Activity;

    if-eqz v2, :cond_13

    check-cast p1, Landroid/app/Activity;

    instance-of v2, p1, La/j/g;

    if-eqz v2, :cond_11

    move-object v2, p1

    check-cast v2, La/j/g;

    invoke-interface {v2}, La/j/g;->a()La/j/d;

    move-result-object v2

    check-cast v2, La/j/h;

    .line 9
    iget-object v2, v2, La/j/h;->b:La/j/d$b;

    .line 10
    sget-object v3, La/j/d$b;->e:La/j/d$b;

    .line 11
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v2

    if-ltz v2, :cond_10

    move v1, v5

    :cond_10
    if-eqz v1, :cond_13

    goto :goto_b

    .line 12
    :cond_11
    iget-boolean v1, p0, La/b/k/h;->L:Z

    if-eqz v1, :cond_13

    :goto_b
    invoke-virtual {p1, v6}, Landroid/app/Activity;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    goto :goto_c

    :cond_12
    move v5, p1

    :cond_13
    :goto_c
    if-eqz v5, :cond_14

    .line 13
    iget-object p1, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, p1, La/b/k/e;

    if-eqz v1, :cond_14

    check-cast p1, La/b/k/e;

    invoke-virtual {p1}, La/b/k/e;->q()V

    :cond_14
    if-nez v0, :cond_15

    .line 14
    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {p0, p1}, La/b/k/h;->C(Landroid/content/Context;)La/b/k/h$g;

    move-result-object p1

    invoke-virtual {p1}, La/b/k/h$g;->e()V

    goto :goto_d

    :cond_15
    iget-object p1, p0, La/b/k/h;->R:La/b/k/h$g;

    if-eqz p1, :cond_16

    invoke-virtual {p1}, La/b/k/h$g;->a()V

    :cond_16
    :goto_d
    const/4 p1, 0x3

    if-ne v0, p1, :cond_18

    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    .line 15
    iget-object v0, p0, La/b/k/h;->S:La/b/k/h$g;

    if-nez v0, :cond_17

    new-instance v0, La/b/k/h$f;

    invoke-direct {v0, p0, p1}, La/b/k/h$f;-><init>(La/b/k/h;Landroid/content/Context;)V

    iput-object v0, p0, La/b/k/h;->S:La/b/k/h$g;

    :cond_17
    iget-object p1, p0, La/b/k/h;->S:La/b/k/h$g;

    .line 16
    invoke-virtual {p1}, La/b/k/h$g;->e()V

    goto :goto_e

    :cond_18
    iget-object p1, p0, La/b/k/h;->S:La/b/k/h$g;

    if-eqz p1, :cond_19

    invoke-virtual {p1}, La/b/k/h$g;->a()V

    :cond_19
    :goto_e
    return v5
.end method

.method public final r(Landroid/view/Window;)V
    .locals 3

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    const-string v1, "AppCompat has already installed itself into the Window"

    if-nez v0, :cond_2

    invoke-virtual {p1}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    move-result-object v0

    instance-of v2, v0, La/b/k/h$e;

    if-nez v2, :cond_1

    new-instance v1, La/b/k/h$e;

    invoke-direct {v1, p0, v0}, La/b/k/h$e;-><init>(La/b/k/h;Landroid/view/Window$Callback;)V

    iput-object v1, p0, La/b/k/h;->g:La/b/k/h$e;

    invoke-virtual {p1, v1}, Landroid/view/Window;->setCallback(Landroid/view/Window$Callback;)V

    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    const/4 v1, 0x0

    sget-object v2, La/b/k/h;->c0:[I

    invoke-static {v0, v1, v2}, La/b/p/x0;->n(Landroid/content/Context;Landroid/util/AttributeSet;[I)La/b/p/x0;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, La/b/p/x0;->f(I)Landroid/graphics/drawable/Drawable;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p1, v1}, Landroid/view/Window;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 1
    :cond_0
    iget-object v0, v0, La/b/p/x0;->b:Landroid/content/res/TypedArray;

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    .line 2
    iput-object p1, p0, La/b/k/h;->f:Landroid/view/Window;

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public s(ILa/b/k/h$k;Landroid/view/Menu;)V
    .locals 0

    if-nez p3, :cond_0

    if-eqz p2, :cond_0

    iget-object p3, p2, La/b/k/h$k;->h:La/b/o/i/g;

    :cond_0
    if-eqz p2, :cond_1

    iget-boolean p2, p2, La/b/k/h$k;->m:Z

    if-nez p2, :cond_1

    return-void

    :cond_1
    iget-boolean p2, p0, La/b/k/h;->M:Z

    if-nez p2, :cond_2

    iget-object p2, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 1
    iget-object p2, p2, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 2
    invoke-interface {p2, p1, p3}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    :cond_2
    return-void
.end method

.method public t(La/b/o/i/g;)V
    .locals 2

    iget-boolean v0, p0, La/b/k/h;->F:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/k/h;->F:Z

    iget-object v0, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {v0}, La/b/p/c0;->j()V

    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-boolean v1, p0, La/b/k/h;->M:Z

    if-nez v1, :cond_1

    const/16 v1, 0x6c

    invoke-interface {v0, v1, p1}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    :cond_1
    const/4 p1, 0x0

    iput-boolean p1, p0, La/b/k/h;->F:Z

    return-void
.end method

.method public u(La/b/k/h$k;Z)V
    .locals 3

    if-eqz p2, :cond_0

    iget v0, p1, La/b/k/h$k;->a:I

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v0, :cond_0

    invoke-interface {v0}, La/b/p/c0;->e()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p1, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {p0, p1}, La/b/k/h;->t(La/b/o/i/g;)V

    return-void

    :cond_0
    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    const-string v1, "window"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/WindowManager;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-boolean v2, p1, La/b/k/h$k;->m:Z

    if-eqz v2, :cond_1

    iget-object v2, p1, La/b/k/h$k;->e:Landroid/view/ViewGroup;

    if-eqz v2, :cond_1

    invoke-interface {v0, v2}, Landroid/view/WindowManager;->removeView(Landroid/view/View;)V

    if-eqz p2, :cond_1

    iget p2, p1, La/b/k/h$k;->a:I

    invoke-virtual {p0, p2, p1, v1}, La/b/k/h;->s(ILa/b/k/h$k;Landroid/view/Menu;)V

    :cond_1
    const/4 p2, 0x0

    iput-boolean p2, p1, La/b/k/h$k;->k:Z

    iput-boolean p2, p1, La/b/k/h$k;->l:Z

    iput-boolean p2, p1, La/b/k/h$k;->m:Z

    iput-object v1, p1, La/b/k/h$k;->f:Landroid/view/View;

    const/4 p2, 0x1

    iput-boolean p2, p1, La/b/k/h$k;->o:Z

    iget-object p2, p0, La/b/k/h;->H:La/b/k/h$k;

    if-ne p2, p1, :cond_2

    iput-object v1, p0, La/b/k/h;->H:La/b/k/h$k;

    :cond_2
    return-void
.end method

.method public final v(Landroid/content/Context;ILandroid/content/res/Configuration;)Landroid/content/res/Configuration;
    .locals 1

    const/4 v0, 0x1

    if-eq p2, v0, :cond_1

    const/4 v0, 0x2

    if-eq p2, v0, :cond_0

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object p1

    iget p1, p1, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 p1, p1, 0x30

    goto :goto_0

    :cond_0
    const/16 p1, 0x20

    goto :goto_0

    :cond_1
    const/16 p1, 0x10

    :goto_0
    new-instance p2, Landroid/content/res/Configuration;

    invoke-direct {p2}, Landroid/content/res/Configuration;-><init>()V

    const/4 v0, 0x0

    iput v0, p2, Landroid/content/res/Configuration;->fontScale:F

    if-eqz p3, :cond_2

    invoke-virtual {p2, p3}, Landroid/content/res/Configuration;->setTo(Landroid/content/res/Configuration;)V

    :cond_2
    iget p3, p2, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 p3, p3, -0x31

    or-int/2addr p1, p3

    iput p1, p2, Landroid/content/res/Configuration;->uiMode:I

    return-object p2
.end method

.method public w(Landroid/view/KeyEvent;)Z
    .locals 6

    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, La/f/j/d$a;

    const/4 v2, 0x1

    if-nez v1, :cond_0

    instance-of v0, v0, La/b/k/n;

    if-eqz v0, :cond_1

    :cond_0
    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 1
    invoke-static {v0, p1}, La/f/j/k;->d(Landroid/view/View;Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_1

    return v2

    .line 2
    :cond_1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    const/16 v1, 0x52

    if-ne v0, v1, :cond_2

    iget-object v0, p0, La/b/k/h;->g:La/b/k/h$e;

    .line 3
    iget-object v0, v0, La/b/o/h;->b:Landroid/view/Window$Callback;

    .line 4
    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_2

    return v2

    :cond_2
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    move-result v3

    const/4 v4, 0x0

    if-nez v3, :cond_3

    move v3, v2

    goto :goto_0

    :cond_3
    move v3, v4

    :goto_0
    const/4 v5, 0x4

    if-eqz v3, :cond_8

    if-eq v0, v5, :cond_5

    if-eq v0, v1, :cond_4

    goto :goto_2

    .line 5
    :cond_4
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getRepeatCount()I

    move-result v0

    if-nez v0, :cond_16

    invoke-virtual {p0, v4}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-boolean v1, v0, La/b/k/h$k;->m:Z

    if-nez v1, :cond_16

    invoke-virtual {p0, v0, p1}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    goto/16 :goto_8

    .line 6
    :cond_5
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getFlags()I

    move-result p1

    and-int/lit16 p1, p1, 0x80

    if-eqz p1, :cond_6

    goto :goto_1

    :cond_6
    move v2, v4

    :goto_1
    iput-boolean v2, p0, La/b/k/h;->I:Z

    :cond_7
    :goto_2
    move v2, v4

    goto/16 :goto_8

    :cond_8
    if-eq v0, v5, :cond_12

    if-eq v0, v1, :cond_9

    goto :goto_2

    .line 7
    :cond_9
    iget-object v0, p0, La/b/k/h;->o:La/b/o/a;

    if-eqz v0, :cond_a

    goto/16 :goto_8

    :cond_a
    invoke-virtual {p0, v4}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v1, :cond_c

    invoke-interface {v1}, La/b/p/c0;->f()Z

    move-result v1

    if-eqz v1, :cond_c

    iget-object v1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-static {v1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/ViewConfiguration;->hasPermanentMenuKey()Z

    move-result v1

    if-nez v1, :cond_c

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {v1}, La/b/p/c0;->e()Z

    move-result v1

    if-nez v1, :cond_b

    iget-boolean v1, p0, La/b/k/h;->M:Z

    if-nez v1, :cond_f

    invoke-virtual {p0, v0, p1}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    move-result p1

    if-eqz p1, :cond_f

    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {p1}, La/b/p/c0;->a()Z

    move-result p1

    goto :goto_5

    :cond_b
    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {p1}, La/b/p/c0;->g()Z

    move-result p1

    goto :goto_5

    :cond_c
    iget-boolean v1, v0, La/b/k/h$k;->m:Z

    if-nez v1, :cond_10

    iget-boolean v1, v0, La/b/k/h$k;->l:Z

    if-eqz v1, :cond_d

    goto :goto_4

    :cond_d
    iget-boolean v1, v0, La/b/k/h$k;->k:Z

    if-eqz v1, :cond_f

    iget-boolean v1, v0, La/b/k/h$k;->p:Z

    if-eqz v1, :cond_e

    iput-boolean v4, v0, La/b/k/h$k;->k:Z

    invoke-virtual {p0, v0, p1}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    move-result v1

    goto :goto_3

    :cond_e
    move v1, v2

    :goto_3
    if-eqz v1, :cond_f

    invoke-virtual {p0, v0, p1}, La/b/k/h;->I(La/b/k/h$k;Landroid/view/KeyEvent;)V

    move p1, v2

    goto :goto_5

    :cond_f
    move p1, v4

    goto :goto_5

    :cond_10
    :goto_4
    iget-boolean p1, v0, La/b/k/h$k;->m:Z

    invoke-virtual {p0, v0, v2}, La/b/k/h;->u(La/b/k/h$k;Z)V

    :goto_5
    if-eqz p1, :cond_16

    iget-object p1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string v0, "audio"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/media/AudioManager;

    if-eqz p1, :cond_11

    invoke-virtual {p1, v4}, Landroid/media/AudioManager;->playSoundEffect(I)V

    goto :goto_8

    :cond_11
    const-string p1, "AppCompatDelegate"

    const-string v0, "Couldn\'t get audio manager"

    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_8

    .line 8
    :cond_12
    iget-boolean p1, p0, La/b/k/h;->I:Z

    iput-boolean v4, p0, La/b/k/h;->I:Z

    invoke-virtual {p0, v4}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-boolean v1, v0, La/b/k/h$k;->m:Z

    if-eqz v1, :cond_13

    if-nez p1, :cond_16

    invoke-virtual {p0, v0, v2}, La/b/k/h;->u(La/b/k/h$k;Z)V

    goto :goto_8

    .line 9
    :cond_13
    iget-object p1, p0, La/b/k/h;->o:La/b/o/a;

    if-eqz p1, :cond_14

    invoke-virtual {p1}, La/b/o/a;->c()V

    goto :goto_6

    .line 10
    :cond_14
    invoke-virtual {p0}, La/b/k/h;->F()V

    iget-object p1, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz p1, :cond_15

    .line 11
    invoke-virtual {p1}, La/b/k/a;->a()Z

    move-result p1

    if-eqz p1, :cond_15

    :goto_6
    move p1, v2

    goto :goto_7

    :cond_15
    move p1, v4

    :goto_7
    if-eqz p1, :cond_7

    :cond_16
    :goto_8
    return v2
.end method

.method public x(I)V
    .locals 3

    invoke-virtual {p0, p1}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-object v1, v0, La/b/k/h$k;->h:La/b/o/i/g;

    if-eqz v1, :cond_1

    new-instance v1, Landroid/os/Bundle;

    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    iget-object v2, v0, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v2, v1}, La/b/o/i/g;->w(Landroid/os/Bundle;)V

    invoke-virtual {v1}, Landroid/os/Bundle;->size()I

    move-result v2

    if-lez v2, :cond_0

    iput-object v1, v0, La/b/k/h$k;->q:Landroid/os/Bundle;

    :cond_0
    iget-object v1, v0, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v1}, La/b/o/i/g;->z()V

    iget-object v1, v0, La/b/k/h$k;->h:La/b/o/i/g;

    invoke-virtual {v1}, La/b/o/i/g;->clear()V

    :cond_1
    const/4 v1, 0x1

    iput-boolean v1, v0, La/b/k/h$k;->p:Z

    iput-boolean v1, v0, La/b/k/h$k;->o:Z

    const/16 v0, 0x6c

    if-eq p1, v0, :cond_2

    if-nez p1, :cond_3

    :cond_2
    iget-object p1, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz p1, :cond_3

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iput-boolean p1, v0, La/b/k/h$k;->k:Z

    const/4 p1, 0x0

    invoke-virtual {p0, v0, p1}, La/b/k/h;->K(La/b/k/h$k;Landroid/view/KeyEvent;)Z

    :cond_3
    return-void
.end method

.method public y()V
    .locals 1

    iget-object v0, p0, La/b/k/h;->s:La/f/j/p;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/f/j/p;->b()V

    :cond_0
    return-void
.end method

.method public final z()V
    .locals 9

    iget-boolean v0, p0, La/b/k/h;->u:Z

    if-nez v0, :cond_1a

    .line 1
    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    sget-object v1, La/b/j;->AppCompatTheme:[I

    invoke-virtual {v0, v1}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object v0

    sget v1, La/b/j;->AppCompatTheme_windowActionBar:I

    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v1

    if-eqz v1, :cond_19

    sget v1, La/b/j;->AppCompatTheme_windowNoTitle:I

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v1

    const/16 v3, 0x6c

    const/4 v4, 0x1

    if-eqz v1, :cond_0

    invoke-virtual {p0, v4}, La/b/k/h;->k(I)Z

    goto :goto_0

    :cond_0
    sget v1, La/b/j;->AppCompatTheme_windowActionBar:I

    invoke-virtual {v0, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p0, v3}, La/b/k/h;->k(I)Z

    :cond_1
    :goto_0
    sget v1, La/b/j;->AppCompatTheme_windowActionBarOverlay:I

    invoke-virtual {v0, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v1

    const/16 v5, 0x6d

    if-eqz v1, :cond_2

    invoke-virtual {p0, v5}, La/b/k/h;->k(I)Z

    :cond_2
    sget v1, La/b/j;->AppCompatTheme_windowActionModeOverlay:I

    invoke-virtual {v0, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v1

    if-eqz v1, :cond_3

    const/16 v1, 0xa

    invoke-virtual {p0, v1}, La/b/k/h;->k(I)Z

    :cond_3
    sget v1, La/b/j;->AppCompatTheme_android_windowIsFloating:I

    invoke-virtual {v0, v1, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v1

    iput-boolean v1, p0, La/b/k/h;->D:Z

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    invoke-virtual {p0}, La/b/k/h;->A()V

    iget-object v0, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    iget-object v0, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    iget-boolean v1, p0, La/b/k/h;->E:Z

    const/4 v6, 0x0

    if-nez v1, :cond_9

    iget-boolean v1, p0, La/b/k/h;->D:Z

    if-eqz v1, :cond_4

    sget v1, La/b/g;->abc_dialog_title_material:I

    invoke-virtual {v0, v1, v6}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    iput-boolean v2, p0, La/b/k/h;->B:Z

    iput-boolean v2, p0, La/b/k/h;->A:Z

    goto/16 :goto_3

    :cond_4
    iget-boolean v0, p0, La/b/k/h;->A:Z

    if-eqz v0, :cond_8

    new-instance v0, Landroid/util/TypedValue;

    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    iget-object v1, p0, La/b/k/h;->e:Landroid/content/Context;

    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v1

    sget v7, La/b/a;->actionBarTheme:I

    invoke-virtual {v1, v7, v0, v4}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v1, v0, Landroid/util/TypedValue;->resourceId:I

    if-eqz v1, :cond_5

    new-instance v1, La/b/o/c;

    iget-object v7, p0, La/b/k/h;->e:Landroid/content/Context;

    iget v0, v0, Landroid/util/TypedValue;->resourceId:I

    invoke-direct {v1, v7, v0}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    goto :goto_1

    :cond_5
    iget-object v1, p0, La/b/k/h;->e:Landroid/content/Context;

    :goto_1
    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    sget v1, La/b/g;->abc_screen_toolbar:I

    invoke-virtual {v0, v1, v6}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    sget v1, La/b/f;->decor_content_parent:I

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, La/b/p/c0;

    iput-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-virtual {p0}, La/b/k/h;->E()Landroid/view/Window$Callback;

    move-result-object v7

    invoke-interface {v1, v7}, La/b/p/c0;->setWindowCallback(Landroid/view/Window$Callback;)V

    iget-boolean v1, p0, La/b/k/h;->B:Z

    if-eqz v1, :cond_6

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    invoke-interface {v1, v5}, La/b/p/c0;->h(I)V

    :cond_6
    iget-boolean v1, p0, La/b/k/h;->y:Z

    if-eqz v1, :cond_7

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    const/4 v5, 0x2

    invoke-interface {v1, v5}, La/b/p/c0;->h(I)V

    :cond_7
    iget-boolean v1, p0, La/b/k/h;->z:Z

    if-eqz v1, :cond_b

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    const/4 v5, 0x5

    invoke-interface {v1, v5}, La/b/p/c0;->h(I)V

    goto :goto_3

    :cond_8
    move-object v0, v6

    goto :goto_3

    :cond_9
    iget-boolean v1, p0, La/b/k/h;->C:Z

    if-eqz v1, :cond_a

    sget v1, La/b/g;->abc_screen_simple_overlay_action_mode:I

    goto :goto_2

    :cond_a
    sget v1, La/b/g;->abc_screen_simple:I

    :goto_2
    invoke-virtual {v0, v1, v6}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    :cond_b
    :goto_3
    if-eqz v0, :cond_18

    new-instance v1, La/b/k/i;

    invoke-direct {v1, p0}, La/b/k/i;-><init>(La/b/k/h;)V

    invoke-static {v0, v1}, La/f/j/k;->x(Landroid/view/View;La/f/j/i;)V

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    if-nez v1, :cond_c

    sget v1, La/b/f;->title:I

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    iput-object v1, p0, La/b/k/h;->w:Landroid/widget/TextView;

    :cond_c
    invoke-static {v0}, La/b/p/d1;->c(Landroid/view/View;)V

    sget v1, La/b/f;->action_bar_activity_content:I

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/widget/ContentFrameLayout;

    iget-object v5, p0, La/b/k/h;->f:Landroid/view/Window;

    const v7, 0x1020002

    invoke-virtual {v5, v7}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object v5

    check-cast v5, Landroid/view/ViewGroup;

    if-eqz v5, :cond_e

    :goto_4
    invoke-virtual {v5}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v8

    if-lez v8, :cond_d

    invoke-virtual {v5, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v8

    invoke-virtual {v5, v2}, Landroid/view/ViewGroup;->removeViewAt(I)V

    invoke-virtual {v1, v8}, Landroid/widget/FrameLayout;->addView(Landroid/view/View;)V

    goto :goto_4

    :cond_d
    const/4 v8, -0x1

    invoke-virtual {v5, v8}, Landroid/view/ViewGroup;->setId(I)V

    invoke-virtual {v1, v7}, Landroid/widget/FrameLayout;->setId(I)V

    instance-of v8, v5, Landroid/widget/FrameLayout;

    if-eqz v8, :cond_e

    check-cast v5, Landroid/widget/FrameLayout;

    invoke-virtual {v5, v6}, Landroid/widget/FrameLayout;->setForeground(Landroid/graphics/drawable/Drawable;)V

    :cond_e
    iget-object v5, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v5, v0}, Landroid/view/Window;->setContentView(Landroid/view/View;)V

    new-instance v5, La/b/k/k;

    invoke-direct {v5, p0}, La/b/k/k;-><init>(La/b/k/h;)V

    invoke-virtual {v1, v5}, Landroidx/appcompat/widget/ContentFrameLayout;->setAttachListener(Landroidx/appcompat/widget/ContentFrameLayout$a;)V

    .line 2
    iput-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    .line 3
    iget-object v0, p0, La/b/k/h;->d:Ljava/lang/Object;

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_f

    check-cast v0, Landroid/app/Activity;

    invoke-virtual {v0}, Landroid/app/Activity;->getTitle()Ljava/lang/CharSequence;

    move-result-object v0

    goto :goto_5

    :cond_f
    iget-object v0, p0, La/b/k/h;->k:Ljava/lang/CharSequence;

    .line 4
    :goto_5
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_12

    iget-object v1, p0, La/b/k/h;->l:La/b/p/c0;

    if-eqz v1, :cond_10

    invoke-interface {v1, v0}, La/b/p/c0;->setWindowTitle(Ljava/lang/CharSequence;)V

    goto :goto_6

    .line 5
    :cond_10
    iget-object v1, p0, La/b/k/h;->i:La/b/k/a;

    if-eqz v1, :cond_11

    .line 6
    invoke-virtual {v1, v0}, La/b/k/a;->i(Ljava/lang/CharSequence;)V

    goto :goto_6

    :cond_11
    iget-object v1, p0, La/b/k/h;->w:Landroid/widget/TextView;

    if-eqz v1, :cond_12

    invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 7
    :cond_12
    :goto_6
    iget-object v0, p0, La/b/k/h;->v:Landroid/view/ViewGroup;

    invoke-virtual {v0, v7}, Landroid/view/ViewGroup;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/ContentFrameLayout;

    iget-object v1, p0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/View;->getPaddingLeft()I

    move-result v5

    invoke-virtual {v1}, Landroid/view/View;->getPaddingTop()I

    move-result v6

    invoke-virtual {v1}, Landroid/view/View;->getPaddingRight()I

    move-result v7

    invoke-virtual {v1}, Landroid/view/View;->getPaddingBottom()I

    move-result v1

    .line 8
    iget-object v8, v0, Landroidx/appcompat/widget/ContentFrameLayout;->h:Landroid/graphics/Rect;

    invoke-virtual {v8, v5, v6, v7, v1}, Landroid/graphics/Rect;->set(IIII)V

    invoke-static {v0}, La/f/j/k;->m(Landroid/view/View;)Z

    move-result v1

    if-eqz v1, :cond_13

    invoke-virtual {v0}, Landroid/widget/FrameLayout;->requestLayout()V

    .line 9
    :cond_13
    iget-object v1, p0, La/b/k/h;->e:Landroid/content/Context;

    sget-object v5, La/b/j;->AppCompatTheme:[I

    invoke-virtual {v1, v5}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object v1

    sget v5, La/b/j;->AppCompatTheme_windowMinWidthMajor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getMinWidthMajor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    sget v5, La/b/j;->AppCompatTheme_windowMinWidthMinor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getMinWidthMinor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    sget v5, La/b/j;->AppCompatTheme_windowFixedWidthMajor:I

    invoke-virtual {v1, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_14

    sget v5, La/b/j;->AppCompatTheme_windowFixedWidthMajor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedWidthMajor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    :cond_14
    sget v5, La/b/j;->AppCompatTheme_windowFixedWidthMinor:I

    invoke-virtual {v1, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_15

    sget v5, La/b/j;->AppCompatTheme_windowFixedWidthMinor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedWidthMinor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    :cond_15
    sget v5, La/b/j;->AppCompatTheme_windowFixedHeightMajor:I

    invoke-virtual {v1, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_16

    sget v5, La/b/j;->AppCompatTheme_windowFixedHeightMajor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedHeightMajor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    :cond_16
    sget v5, La/b/j;->AppCompatTheme_windowFixedHeightMinor:I

    invoke-virtual {v1, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_17

    sget v5, La/b/j;->AppCompatTheme_windowFixedHeightMinor:I

    invoke-virtual {v0}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedHeightMinor()Landroid/util/TypedValue;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    :cond_17
    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V

    invoke-virtual {v0}, Landroid/widget/FrameLayout;->requestLayout()V

    .line 10
    iput-boolean v4, p0, La/b/k/h;->u:Z

    invoke-virtual {p0, v2}, La/b/k/h;->D(I)La/b/k/h$k;

    move-result-object v0

    iget-boolean v1, p0, La/b/k/h;->M:Z

    if-nez v1, :cond_1a

    iget-object v0, v0, La/b/k/h$k;->h:La/b/o/i/g;

    if-nez v0, :cond_1a

    invoke-virtual {p0, v3}, La/b/k/h;->G(I)V

    goto :goto_7

    .line 11
    :cond_18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "AppCompat does not support the current theme features: { windowActionBar: "

    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    iget-boolean v2, p0, La/b/k/h;->A:Z

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v2, ", windowActionBarOverlay: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v2, p0, La/b/k/h;->B:Z

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v2, ", android:windowIsFloating: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v2, p0, La/b/k/h;->D:Z

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v2, ", windowActionModeOverlay: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v2, p0, La/b/k/h;->C:Z

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v2, ", windowNoTitle: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v2, p0, La/b/k/h;->E:Z

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v2, " }"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_19
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You need to use a Theme.AppCompat theme (or descendant) with this activity."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1a
    :goto_7
    return-void
.end method
