.class public La/b/k/e;
.super La/i/a/d;
.source ""

# interfaces
.implements La/b/k/f;
.implements La/f/c/f;


# instance fields
.field public n:La/b/k/g;

.field public o:Landroid/content/res/Resources;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, La/i/a/d;-><init>()V

    return-void
.end method


# virtual methods
.method public addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, La/b/k/g;->c(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public attachBaseContext(Landroid/content/Context;)V
    .locals 9

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    const/4 v1, 0x1

    .line 1
    iput-boolean v1, v0, La/b/k/h;->J:Z

    .line 2
    iget v2, v0, La/b/k/h;->N:I

    const/16 v3, -0x64

    if-eq v2, v3, :cond_0

    goto :goto_0

    :cond_0
    move v2, v3

    .line 3
    :goto_0
    invoke-virtual {v0, p1, v2}, La/b/k/h;->H(Landroid/content/Context;I)I

    move-result v2

    sget-boolean v3, La/b/k/h;->e0:Z

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    instance-of v3, p1, Landroid/view/ContextThemeWrapper;

    if-eqz v3, :cond_1

    invoke-virtual {v0, p1, v2, v4}, La/b/k/h;->v(Landroid/content/Context;ILandroid/content/res/Configuration;)Landroid/content/res/Configuration;

    move-result-object v3

    :try_start_0
    move-object v5, p1

    check-cast v5, Landroid/view/ContextThemeWrapper;

    .line 4
    invoke-virtual {v5, v3}, Landroid/view/ContextThemeWrapper;->applyOverrideConfiguration(Landroid/content/res/Configuration;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_7

    .line 5
    :catch_0
    :cond_1
    instance-of v3, p1, La/b/o/c;

    if-eqz v3, :cond_2

    invoke-virtual {v0, p1, v2, v4}, La/b/k/h;->v(Landroid/content/Context;ILandroid/content/res/Configuration;)Landroid/content/res/Configuration;

    move-result-object v3

    :try_start_1
    move-object v5, p1

    check-cast v5, La/b/o/c;

    invoke-virtual {v5, v3}, La/b/o/c;->a(Landroid/content/res/Configuration;)V
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_1

    goto/16 :goto_7

    :catch_1
    :cond_2
    sget-boolean v3, La/b/k/h;->d0:Z

    if-nez v3, :cond_3

    goto/16 :goto_7

    :cond_3
    :try_start_2
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v3

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object v5

    invoke-virtual {v3, v5}, Landroid/content/pm/PackageManager;->getResourcesForApplication(Landroid/content/pm/ApplicationInfo;)Landroid/content/res/Resources;

    move-result-object v3

    invoke-virtual {v3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v3
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_6

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v5

    invoke-virtual {v3, v5}, Landroid/content/res/Configuration;->equals(Landroid/content/res/Configuration;)Z

    move-result v6

    if-nez v6, :cond_1a

    .line 6
    new-instance v6, Landroid/content/res/Configuration;

    invoke-direct {v6}, Landroid/content/res/Configuration;-><init>()V

    const/4 v7, 0x0

    iput v7, v6, Landroid/content/res/Configuration;->fontScale:F

    if-eqz v5, :cond_1b

    invoke-virtual {v3, v5}, Landroid/content/res/Configuration;->diff(Landroid/content/res/Configuration;)I

    move-result v7

    if-nez v7, :cond_4

    goto/16 :goto_1

    :cond_4
    iget v7, v3, Landroid/content/res/Configuration;->fontScale:F

    iget v8, v5, Landroid/content/res/Configuration;->fontScale:F

    cmpl-float v7, v7, v8

    if-eqz v7, :cond_5

    iput v8, v6, Landroid/content/res/Configuration;->fontScale:F

    :cond_5
    iget v7, v3, Landroid/content/res/Configuration;->mcc:I

    iget v8, v5, Landroid/content/res/Configuration;->mcc:I

    if-eq v7, v8, :cond_6

    iput v8, v6, Landroid/content/res/Configuration;->mcc:I

    :cond_6
    iget v7, v3, Landroid/content/res/Configuration;->mnc:I

    iget v8, v5, Landroid/content/res/Configuration;->mnc:I

    if-eq v7, v8, :cond_7

    iput v8, v6, Landroid/content/res/Configuration;->mnc:I

    .line 7
    :cond_7
    invoke-virtual {v3}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    move-result-object v7

    invoke-virtual {v5}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    move-result-object v8

    invoke-virtual {v7, v8}, Landroid/os/LocaleList;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_8

    invoke-virtual {v6, v8}, Landroid/content/res/Configuration;->setLocales(Landroid/os/LocaleList;)V

    iget-object v7, v5, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    iput-object v7, v6, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 8
    :cond_8
    iget v7, v3, Landroid/content/res/Configuration;->touchscreen:I

    iget v8, v5, Landroid/content/res/Configuration;->touchscreen:I

    if-eq v7, v8, :cond_9

    iput v8, v6, Landroid/content/res/Configuration;->touchscreen:I

    :cond_9
    iget v7, v3, Landroid/content/res/Configuration;->keyboard:I

    iget v8, v5, Landroid/content/res/Configuration;->keyboard:I

    if-eq v7, v8, :cond_a

    iput v8, v6, Landroid/content/res/Configuration;->keyboard:I

    :cond_a
    iget v7, v3, Landroid/content/res/Configuration;->keyboardHidden:I

    iget v8, v5, Landroid/content/res/Configuration;->keyboardHidden:I

    if-eq v7, v8, :cond_b

    iput v8, v6, Landroid/content/res/Configuration;->keyboardHidden:I

    :cond_b
    iget v7, v3, Landroid/content/res/Configuration;->navigation:I

    iget v8, v5, Landroid/content/res/Configuration;->navigation:I

    if-eq v7, v8, :cond_c

    iput v8, v6, Landroid/content/res/Configuration;->navigation:I

    :cond_c
    iget v7, v3, Landroid/content/res/Configuration;->navigationHidden:I

    iget v8, v5, Landroid/content/res/Configuration;->navigationHidden:I

    if-eq v7, v8, :cond_d

    iput v8, v6, Landroid/content/res/Configuration;->navigationHidden:I

    :cond_d
    iget v7, v3, Landroid/content/res/Configuration;->orientation:I

    iget v8, v5, Landroid/content/res/Configuration;->orientation:I

    if-eq v7, v8, :cond_e

    iput v8, v6, Landroid/content/res/Configuration;->orientation:I

    :cond_e
    iget v7, v3, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit8 v7, v7, 0xf

    iget v8, v5, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit8 v8, v8, 0xf

    if-eq v7, v8, :cond_f

    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    :cond_f
    iget v7, v3, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit16 v7, v7, 0xc0

    iget v8, v5, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit16 v8, v8, 0xc0

    if-eq v7, v8, :cond_10

    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    :cond_10
    iget v7, v3, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit8 v7, v7, 0x30

    iget v8, v5, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit8 v8, v8, 0x30

    if-eq v7, v8, :cond_11

    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    :cond_11
    iget v7, v3, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit16 v7, v7, 0x300

    iget v8, v5, Landroid/content/res/Configuration;->screenLayout:I

    and-int/lit16 v8, v8, 0x300

    if-eq v7, v8, :cond_12

    iget v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->screenLayout:I

    :cond_12
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v8, 0x1a

    if-lt v7, v8, :cond_14

    .line 9
    iget v7, v3, Landroid/content/res/Configuration;->colorMode:I

    and-int/lit8 v7, v7, 0x3

    iget v8, v5, Landroid/content/res/Configuration;->colorMode:I

    and-int/lit8 v8, v8, 0x3

    if-eq v7, v8, :cond_13

    iget v7, v6, Landroid/content/res/Configuration;->colorMode:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->colorMode:I

    :cond_13
    iget v7, v3, Landroid/content/res/Configuration;->colorMode:I

    and-int/lit8 v7, v7, 0xc

    iget v8, v5, Landroid/content/res/Configuration;->colorMode:I

    and-int/lit8 v8, v8, 0xc

    if-eq v7, v8, :cond_14

    iget v7, v6, Landroid/content/res/Configuration;->colorMode:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->colorMode:I

    .line 10
    :cond_14
    iget v7, v3, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v7, v7, 0xf

    iget v8, v5, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v8, v8, 0xf

    if-eq v7, v8, :cond_15

    iget v7, v6, Landroid/content/res/Configuration;->uiMode:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->uiMode:I

    :cond_15
    iget v7, v3, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v7, v7, 0x30

    iget v8, v5, Landroid/content/res/Configuration;->uiMode:I

    and-int/lit8 v8, v8, 0x30

    if-eq v7, v8, :cond_16

    iget v7, v6, Landroid/content/res/Configuration;->uiMode:I

    or-int/2addr v7, v8

    iput v7, v6, Landroid/content/res/Configuration;->uiMode:I

    :cond_16
    iget v7, v3, Landroid/content/res/Configuration;->screenWidthDp:I

    iget v8, v5, Landroid/content/res/Configuration;->screenWidthDp:I

    if-eq v7, v8, :cond_17

    iput v8, v6, Landroid/content/res/Configuration;->screenWidthDp:I

    :cond_17
    iget v7, v3, Landroid/content/res/Configuration;->screenHeightDp:I

    iget v8, v5, Landroid/content/res/Configuration;->screenHeightDp:I

    if-eq v7, v8, :cond_18

    iput v8, v6, Landroid/content/res/Configuration;->screenHeightDp:I

    :cond_18
    iget v7, v3, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    iget v8, v5, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    if-eq v7, v8, :cond_19

    iput v8, v6, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    .line 11
    :cond_19
    iget v3, v3, Landroid/content/res/Configuration;->densityDpi:I

    iget v5, v5, Landroid/content/res/Configuration;->densityDpi:I

    if-eq v3, v5, :cond_1b

    iput v5, v6, Landroid/content/res/Configuration;->densityDpi:I

    goto :goto_1

    :cond_1a
    move-object v6, v4

    .line 12
    :cond_1b
    :goto_1
    invoke-virtual {v0, p1, v2, v6}, La/b/k/h;->v(Landroid/content/Context;ILandroid/content/res/Configuration;)Landroid/content/res/Configuration;

    move-result-object v0

    new-instance v2, La/b/o/c;

    sget v3, La/b/i;->Theme_AppCompat_Empty:I

    invoke-direct {v2, p1, v3}, La/b/o/c;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v2, v0}, La/b/o/c;->a(Landroid/content/res/Configuration;)V

    const/4 v0, 0x0

    :try_start_3
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p1
    :try_end_3
    .catch Ljava/lang/NullPointerException; {:try_start_3 .. :try_end_3} :catch_2

    if-eqz p1, :cond_1c

    move p1, v1

    goto :goto_2

    :catch_2
    :cond_1c
    move p1, v0

    :goto_2
    if-eqz p1, :cond_20

    invoke-virtual {v2}, La/b/o/c;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p1

    .line 13
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1d

    if-lt v3, v5, :cond_1d

    .line 14
    invoke-virtual {p1}, Landroid/content/res/Resources$Theme;->rebase()V

    goto :goto_6

    .line 15
    :cond_1d
    sget-object v3, La/f/d/b/f;->a:Ljava/lang/Object;

    monitor-enter v3

    :try_start_4
    sget-boolean v5, La/f/d/b/f;->c:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    if-nez v5, :cond_1e

    :try_start_5
    const-class v5, Landroid/content/res/Resources$Theme;

    const-string v6, "rebase"

    new-array v7, v0, [Ljava/lang/Class;

    invoke-virtual {v5, v6, v7}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v5

    sput-object v5, La/f/d/b/f;->b:Ljava/lang/reflect/Method;

    invoke-virtual {v5, v1}, Ljava/lang/reflect/Method;->setAccessible(Z)V
    :try_end_5
    .catch Ljava/lang/NoSuchMethodException; {:try_start_5 .. :try_end_5} :catch_3
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    goto :goto_3

    :catch_3
    move-exception v5

    :try_start_6
    const-string v6, "ResourcesCompat"

    const-string v7, "Failed to retrieve rebase() method"

    invoke-static {v6, v7, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_3
    sput-boolean v1, La/f/d/b/f;->c:Z

    :cond_1e
    sget-object v1, La/f/d/b/f;->b:Ljava/lang/reflect/Method;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    if-eqz v1, :cond_1f

    :try_start_7
    sget-object v1, La/f/d/b/f;->b:Ljava/lang/reflect/Method;

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {v1, p1, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_7
    .catch Ljava/lang/IllegalAccessException; {:try_start_7 .. :try_end_7} :catch_5
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_7 .. :try_end_7} :catch_4
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    goto :goto_5

    :catch_4
    move-exception p1

    goto :goto_4

    :catch_5
    move-exception p1

    :goto_4
    :try_start_8
    const-string v0, "ResourcesCompat"

    const-string v1, "Failed to invoke rebase() method via reflection"

    invoke-static {v0, v1, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    sput-object v4, La/f/d/b/f;->b:Ljava/lang/reflect/Method;

    :cond_1f
    :goto_5
    monitor-exit v3

    goto :goto_6

    :catchall_0
    move-exception p1

    monitor-exit v3
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    throw p1

    :cond_20
    :goto_6
    move-object p1, v2

    .line 16
    :goto_7
    invoke-super {p0, p1}, Landroid/app/Activity;->attachBaseContext(Landroid/content/Context;)V

    return-void

    :catch_6
    move-exception p1

    .line 17
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "Application failed to obtain resources from itself"

    invoke-direct {v0, v1, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public b(La/b/o/a;)V
    .locals 0

    return-void
.end method

.method public closeOptionsMenu()V
    .locals 3

    invoke-virtual {p0}, La/b/k/e;->p()La/b/k/a;

    move-result-object v0

    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/view/Window;->hasFeature(I)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-super {p0}, Landroid/app/Activity;->closeOptionsMenu()V

    :cond_0
    return-void
.end method

.method public dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 3

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    invoke-virtual {p0}, La/b/k/e;->p()La/b/k/a;

    move-result-object v1

    const/16 v2, 0x52

    invoke-super {p0, p1}, La/f/c/d;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public f(La/b/o/a;)V
    .locals 0

    return-void
.end method

.method public findViewById(I)Landroid/view/View;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Landroid/view/View;",
            ">(I)TT;"
        }
    .end annotation

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    invoke-virtual {v0}, La/b/k/h;->z()V

    iget-object v0, v0, La/b/k/h;->f:Landroid/view/Window;

    invoke-virtual {v0, p1}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public g(La/b/o/a$a;)La/b/o/a;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public getMenuInflater()Landroid/view/MenuInflater;
    .locals 3

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    iget-object v1, v0, La/b/k/h;->j:Landroid/view/MenuInflater;

    if-nez v1, :cond_1

    invoke-virtual {v0}, La/b/k/h;->F()V

    new-instance v1, La/b/o/f;

    iget-object v2, v0, La/b/k/h;->i:La/b/k/a;

    if-eqz v2, :cond_0

    invoke-virtual {v2}, La/b/k/a;->d()Landroid/content/Context;

    move-result-object v2

    goto :goto_0

    :cond_0
    iget-object v2, v0, La/b/k/h;->e:Landroid/content/Context;

    :goto_0
    invoke-direct {v1, v2}, La/b/o/f;-><init>(Landroid/content/Context;)V

    iput-object v1, v0, La/b/k/h;->j:Landroid/view/MenuInflater;

    :cond_1
    iget-object v0, v0, La/b/k/h;->j:Landroid/view/MenuInflater;

    return-object v0
.end method

.method public getResources()Landroid/content/res/Resources;
    .locals 1

    iget-object v0, p0, La/b/k/e;->o:Landroid/content/res/Resources;

    if-nez v0, :cond_0

    invoke-static {}, La/b/p/c1;->a()Z

    :cond_0
    iget-object v0, p0, La/b/k/e;->o:Landroid/content/res/Resources;

    if-nez v0, :cond_1

    invoke-super {p0}, Landroid/app/Activity;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    :cond_1
    return-object v0
.end method

.method public i()Landroid/content/Intent;
    .locals 1

    invoke-static {p0}, La/b/k/h$i;->k(Landroid/app/Activity;)Landroid/content/Intent;

    move-result-object v0

    return-object v0
.end method

.method public invalidateOptionsMenu()V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->g()V

    return-void
.end method

.method public n()V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->g()V

    return-void
.end method

.method public o()La/b/k/g;
    .locals 1

    iget-object v0, p0, La/b/k/e;->n:La/b/k/g;

    if-nez v0, :cond_0

    invoke-static {p0, p0}, La/b/k/g;->d(Landroid/app/Activity;La/b/k/f;)La/b/k/g;

    move-result-object v0

    iput-object v0, p0, La/b/k/e;->n:La/b/k/g;

    :cond_0
    iget-object v0, p0, La/b/k/e;->n:La/b/k/g;

    return-object v0
.end method

.method public onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 8

    invoke-super {p0, p1}, La/i/a/d;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    iget-object v0, p0, La/b/k/e;->o:Landroid/content/res/Resources;

    if-eqz v0, :cond_0

    invoke-super {p0}, Landroid/app/Activity;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    iget-object v1, p0, La/b/k/e;->o:Landroid/content/res/Resources;

    invoke-virtual {v1, p1, v0}, Landroid/content/res/Resources;->updateConfiguration(Landroid/content/res/Configuration;Landroid/util/DisplayMetrics;)V

    :cond_0
    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    iget-boolean v1, v0, La/b/k/h;->A:Z

    if-eqz v1, :cond_1

    iget-boolean v1, v0, La/b/k/h;->u:Z

    if-eqz v1, :cond_1

    .line 2
    invoke-virtual {v0}, La/b/k/h;->F()V

    iget-object v1, v0, La/b/k/h;->i:La/b/k/a;

    if-eqz v1, :cond_1

    .line 3
    invoke-virtual {v1, p1}, La/b/k/a;->e(Landroid/content/res/Configuration;)V

    :cond_1
    invoke-static {}, La/b/p/j;->a()La/b/p/j;

    move-result-object p1

    iget-object v1, v0, La/b/k/h;->e:Landroid/content/Context;

    .line 4
    monitor-enter p1

    :try_start_0
    iget-object v2, p1, La/b/p/j;->a:La/b/p/n0;

    .line 5
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    iget-object v3, v2, La/b/p/n0;->d:Ljava/util/WeakHashMap;

    invoke-virtual {v3, v1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, La/d/e;

    const/4 v3, 0x0

    if-eqz v1, :cond_3

    .line 6
    iget v4, v1, La/d/e;->e:I

    iget-object v5, v1, La/d/e;->d:[Ljava/lang/Object;

    move v6, v3

    :goto_0
    if-ge v6, v4, :cond_2

    const/4 v7, 0x0

    aput-object v7, v5, v6

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_2
    iput v3, v1, La/d/e;->e:I

    iput-boolean v3, v1, La/d/e;->b:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 7
    :cond_3
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 8
    monitor-exit p1

    .line 9
    invoke-virtual {v0, v3}, La/b/k/h;->q(Z)Z

    return-void

    :catchall_0
    move-exception v0

    .line 10
    :try_start_3
    monitor-exit v2

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :catchall_1
    move-exception v0

    monitor-exit p1

    throw v0
.end method

.method public onContentChanged()V
    .locals 0

    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->f()V

    invoke-virtual {v0, p1}, La/b/k/g;->h(Landroid/os/Bundle;)V

    invoke-super {p0, p1}, La/i/a/d;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method

.method public onDestroy()V
    .locals 1

    invoke-super {p0}, La/i/a/d;->onDestroy()V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0}, La/b/k/g;->i()V

    return-void
.end method

.method public onKeyDown(ILandroid/view/KeyEvent;)Z
    .locals 3

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    const/4 v2, 0x1

    if-ge v0, v1, :cond_0

    invoke-virtual {p2}, Landroid/view/KeyEvent;->isCtrlPressed()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p2}, Landroid/view/KeyEvent;->getMetaState()I

    move-result v0

    invoke-static {v0}, Landroid/view/KeyEvent;->metaStateHasNoModifiers(I)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p2}, Landroid/view/KeyEvent;->getRepeatCount()I

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p2}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    invoke-static {v0}, Landroid/view/KeyEvent;->isModifierKey(I)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0, p2}, Landroid/view/View;->dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    return v2

    .line 2
    :cond_1
    invoke-super {p0, p1, p2}, Landroid/app/Activity;->onKeyDown(ILandroid/view/KeyEvent;)Z

    move-result p1

    return p1
.end method

.method public final onMenuItemSelected(ILandroid/view/MenuItem;)Z
    .locals 4

    invoke-super {p0, p1, p2}, La/i/a/d;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    move-result p1

    const/4 v0, 0x1

    if-eqz p1, :cond_0

    return v0

    :cond_0
    invoke-virtual {p0}, La/b/k/e;->p()La/b/k/a;

    move-result-object p1

    invoke-interface {p2}, Landroid/view/MenuItem;->getItemId()I

    move-result p2

    const v1, 0x102002c

    const/4 v2, 0x0

    if-ne p2, v1, :cond_8

    if-eqz p1, :cond_8

    invoke-virtual {p1}, La/b/k/a;->c()I

    move-result p1

    and-int/lit8 p1, p1, 0x4

    if-eqz p1, :cond_8

    .line 1
    invoke-static {p0}, La/b/k/h$i;->k(Landroid/app/Activity;)Landroid/content/Intent;

    move-result-object p1

    if-eqz p1, :cond_7

    .line 2
    invoke-virtual {p0, p1}, Landroid/app/Activity;->shouldUpRecreateTask(Landroid/content/Intent;)Z

    move-result p2

    if-eqz p2, :cond_6

    .line 3
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 4
    invoke-interface {p0}, La/f/c/f;->i()Landroid/content/Intent;

    move-result-object p2

    if-nez p2, :cond_1

    invoke-static {p0}, La/b/k/h$i;->k(Landroid/app/Activity;)Landroid/content/Intent;

    move-result-object p2

    :cond_1
    if-eqz p2, :cond_4

    invoke-virtual {p2}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;

    move-result-object v1

    if-nez v1, :cond_2

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual {p2, v1}, Landroid/content/Intent;->resolveActivity(Landroid/content/pm/PackageManager;)Landroid/content/ComponentName;

    move-result-object v1

    .line 5
    :cond_2
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v3

    :goto_0
    :try_start_0
    invoke-static {p0, v1}, La/b/k/h$i;->l(Landroid/content/Context;Landroid/content/ComponentName;)Landroid/content/Intent;

    move-result-object v1

    if-eqz v1, :cond_3

    invoke-virtual {p1, v3, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    invoke-virtual {v1}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;

    move-result-object v1
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 6
    :cond_3
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :catch_0
    move-exception p1

    const-string p2, "TaskStackBuilder"

    const-string v0, "Bad ComponentName while traversing activity parent metadata"

    .line 7
    invoke-static {p2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw p2

    .line 8
    :cond_4
    :goto_1
    invoke-virtual {p0}, La/b/k/e;->r()V

    .line 9
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_5

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p2

    new-array p2, p2, [Landroid/content/Intent;

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Landroid/content/Intent;

    new-instance p2, Landroid/content/Intent;

    aget-object v1, p1, v2

    invoke-direct {p2, v1}, Landroid/content/Intent;-><init>(Landroid/content/Intent;)V

    const v1, 0x1000c000

    invoke-virtual {p2, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    move-result-object p2

    aput-object p2, p1, v2

    const/4 p2, 0x0

    invoke-static {p0, p1, p2}, La/f/d/a;->c(Landroid/content/Context;[Landroid/content/Intent;Landroid/os/Bundle;)Z

    .line 10
    :try_start_1
    invoke-static {p0}, La/f/c/a;->d(Landroid/app/Activity;)V
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_2

    :catch_1
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    goto :goto_2

    .line 11
    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "No intents added to TaskStackBuilder; cannot startActivities"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 12
    :cond_6
    invoke-virtual {p0, p1}, Landroid/app/Activity;->navigateUpTo(Landroid/content/Intent;)Z

    goto :goto_2

    :cond_7
    move v0, v2

    :goto_2
    return v0

    :cond_8
    return v2
.end method

.method public onMenuOpened(ILandroid/view/Menu;)Z
    .locals 0

    invoke-super {p0, p1, p2}, Landroid/app/Activity;->onMenuOpened(ILandroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public onPanelClosed(ILandroid/view/Menu;)V
    .locals 0

    invoke-super {p0, p1, p2}, La/i/a/d;->onPanelClosed(ILandroid/view/Menu;)V

    return-void
.end method

.method public onPostCreate(Landroid/os/Bundle;)V
    .locals 0

    invoke-super {p0, p1}, Landroid/app/Activity;->onPostCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object p1

    check-cast p1, La/b/k/h;

    .line 1
    invoke-virtual {p1}, La/b/k/h;->z()V

    return-void
.end method

.method public onPostResume()V
    .locals 2

    invoke-super {p0}, La/i/a/d;->onPostResume()V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    invoke-virtual {v0}, La/b/k/h;->F()V

    iget-object v0, v0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    .line 2
    invoke-virtual {v0, v1}, La/b/k/a;->h(Z)V

    :cond_0
    return-void
.end method

.method public onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 0

    invoke-super {p0, p1}, La/i/a/d;->onSaveInstanceState(Landroid/os/Bundle;)V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object p1

    check-cast p1, La/b/k/h;

    if-eqz p1, :cond_0

    return-void

    :cond_0
    const/4 p1, 0x0

    .line 1
    throw p1
.end method

.method public onStart()V
    .locals 2

    invoke-super {p0}, La/i/a/d;->onStart()V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    const/4 v1, 0x1

    .line 1
    iput-boolean v1, v0, La/b/k/h;->L:Z

    invoke-virtual {v0}, La/b/k/h;->p()Z

    return-void
.end method

.method public onStop()V
    .locals 2

    invoke-super {p0}, La/i/a/d;->onStop()V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    const/4 v1, 0x0

    .line 1
    iput-boolean v1, v0, La/b/k/h;->L:Z

    .line 2
    invoke-virtual {v0}, La/b/k/h;->F()V

    iget-object v0, v0, La/b/k/h;->i:La/b/k/a;

    if-eqz v0, :cond_0

    .line 3
    invoke-virtual {v0, v1}, La/b/k/a;->h(Z)V

    :cond_0
    return-void
.end method

.method public onTitleChanged(Ljava/lang/CharSequence;I)V
    .locals 0

    invoke-super {p0, p1, p2}, Landroid/app/Activity;->onTitleChanged(Ljava/lang/CharSequence;I)V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object p2

    invoke-virtual {p2, p1}, La/b/k/g;->o(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public openOptionsMenu()V
    .locals 3

    invoke-virtual {p0}, La/b/k/e;->p()La/b/k/a;

    move-result-object v0

    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/view/Window;->hasFeature(I)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-super {p0}, Landroid/app/Activity;->openOptionsMenu()V

    :cond_0
    return-void
.end method

.method public p()La/b/k/a;
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    invoke-virtual {v0}, La/b/k/h;->F()V

    iget-object v0, v0, La/b/k/h;->i:La/b/k/a;

    return-object v0
.end method

.method public q()V
    .locals 0

    return-void
.end method

.method public r()V
    .locals 0

    return-void
.end method

.method public setContentView(I)V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->l(I)V

    return-void
.end method

.method public setContentView(Landroid/view/View;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1}, La/b/k/g;->m(Landroid/view/View;)V

    return-void
.end method

.method public setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, La/b/k/g;->n(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public setTheme(I)V
    .locals 1

    invoke-super {p0, p1}, Landroid/app/Activity;->setTheme(I)V

    invoke-virtual {p0}, La/b/k/e;->o()La/b/k/g;

    move-result-object v0

    check-cast v0, La/b/k/h;

    .line 1
    iput p1, v0, La/b/k/h;->O:I

    return-void
.end method
