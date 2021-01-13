.class public La/b/k/h$i;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/b/k/h;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "i"
.end annotation


# static fields
.field public static a:Ljava/lang/reflect/Field;

.field public static b:Z

.field public static c:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field public static d:Z

.field public static e:Ljava/lang/reflect/Field;

.field public static f:Z

.field public static g:Ljava/lang/reflect/Field;

.field public static h:Z


# direct methods
.method public static A(Landroid/widget/TextView;La/f/h/a;)V
    .locals 3

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/4 v1, 0x0

    const/16 v2, 0x1d

    if-lt v0, v2, :cond_1

    if-eqz p1, :cond_0

    invoke-virtual {p0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    return-void

    .line 1
    :cond_0
    throw v1

    .line 2
    :cond_1
    invoke-static {p0}, La/b/k/h$i;->o(Landroid/widget/TextView;)La/f/h/a$a;

    if-eqz p1, :cond_2

    throw v1

    .line 3
    :cond_2
    throw v1
.end method

.method public static B(Landroid/view/View;Ljava/lang/CharSequence;)V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_0

    invoke-virtual {p0, p1}, Landroid/view/View;->setTooltipText(Ljava/lang/CharSequence;)V

    goto :goto_0

    .line 1
    :cond_0
    sget-object v0, La/b/p/a1;->k:La/b/p/a1;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, v0, La/b/p/a1;->b:Landroid/view/View;

    if-ne v0, p0, :cond_1

    invoke-static {v1}, La/b/p/a1;->c(La/b/p/a1;)V

    :cond_1
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_3

    sget-object p1, La/b/p/a1;->l:La/b/p/a1;

    if-eqz p1, :cond_2

    iget-object v0, p1, La/b/p/a1;->b:Landroid/view/View;

    if-ne v0, p0, :cond_2

    invoke-virtual {p1}, La/b/p/a1;->b()V

    :cond_2
    invoke-virtual {p0, v1}, Landroid/view/View;->setOnLongClickListener(Landroid/view/View$OnLongClickListener;)V

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/View;->setLongClickable(Z)V

    invoke-virtual {p0, v1}, Landroid/view/View;->setOnHoverListener(Landroid/view/View$OnHoverListener;)V

    goto :goto_0

    :cond_3
    new-instance v0, La/b/p/a1;

    invoke-direct {v0, p0, p1}, La/b/p/a1;-><init>(Landroid/view/View;Ljava/lang/CharSequence;)V

    :goto_0
    return-void
.end method

.method public static C(Lorg/xmlpull/v1/XmlPullParser;)V
    .locals 3

    const/4 v0, 0x1

    :goto_0
    if-lez v0, :cond_2

    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v1

    const/4 v2, 0x2

    if-eq v1, v2, :cond_1

    const/4 v2, 0x3

    if-eq v1, v2, :cond_0

    goto :goto_0

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public static D([Ljava/lang/String;)Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "[B>;"
        }
    .end annotation

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    array-length v1, p0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, p0, v3

    invoke-static {v4, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public static E(La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;La/e/b/h/d$a;)Z
    .locals 5

    sget-object v0, La/e/b/h/d$a;->e:La/e/b/h/d$a;

    sget-object v1, La/e/b/h/d$a;->b:La/e/b/h/d$a;

    sget-object v2, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eq p2, v1, :cond_1

    if-eq p2, v2, :cond_1

    if-ne p2, v0, :cond_0

    if-eq p0, v2, :cond_0

    goto :goto_0

    :cond_0
    move p0, v3

    goto :goto_1

    :cond_1
    :goto_0
    move p0, v4

    :goto_1
    if-eq p3, v1, :cond_3

    if-eq p3, v2, :cond_3

    if-ne p3, v0, :cond_2

    if-eq p1, v2, :cond_2

    goto :goto_2

    :cond_2
    move p1, v3

    goto :goto_3

    :cond_3
    :goto_2
    move p1, v4

    :goto_3
    if-nez p0, :cond_5

    if-eqz p1, :cond_4

    goto :goto_4

    :cond_4
    return v3

    :cond_5
    :goto_4
    return v4
.end method

.method public static F(Landroid/widget/TextView;Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode$Callback;
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_1

    const/16 v1, 0x1b

    if-gt v0, v1, :cond_1

    instance-of v0, p1, La/f/k/d;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, La/f/k/d;

    invoke-direct {v0, p1, p0}, La/f/k/d;-><init>(Landroid/view/ActionMode$Callback;Landroid/widget/TextView;)V

    return-object v0

    :cond_1
    :goto_0
    return-object p1
.end method

.method public static a(La/e/b/h/e;La/e/b/d;Ljava/util/ArrayList;I)V
    .locals 37
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/e/b/h/e;",
            "La/e/b/d;",
            "Ljava/util/ArrayList<",
            "La/e/b/h/d;",
            ">;I)V"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v10, p1

    move-object/from16 v11, p2

    sget-object v12, La/e/b/h/d$a;->d:La/e/b/h/d$a;

    const/4 v13, 0x2

    if-nez p3, :cond_0

    iget v1, v0, La/e/b/h/e;->w0:I

    iget-object v2, v0, La/e/b/h/e;->z0:[La/e/b/h/b;

    move v15, v1

    move-object/from16 v16, v2

    const/16 v17, 0x0

    goto :goto_0

    :cond_0
    iget v1, v0, La/e/b/h/e;->x0:I

    iget-object v2, v0, La/e/b/h/e;->y0:[La/e/b/h/b;

    move v15, v1

    move-object/from16 v16, v2

    move/from16 v17, v13

    :goto_0
    const/4 v9, 0x0

    :goto_1
    if-ge v9, v15, :cond_6f

    aget-object v1, v16, v9

    .line 1
    iget-boolean v2, v1, La/e/b/h/b;->t:Z

    const/16 v18, 0x0

    const/16 v8, 0x8

    const/4 v4, 0x1

    if-nez v2, :cond_19

    .line 2
    iget v2, v1, La/e/b/h/b;->o:I

    mul-int/2addr v2, v13

    iget-object v5, v1, La/e/b/h/b;->a:La/e/b/h/d;

    move-object v6, v5

    const/4 v7, 0x0

    :goto_2
    if-nez v7, :cond_14

    iget v14, v1, La/e/b/h/b;->i:I

    add-int/2addr v14, v4

    iput v14, v1, La/e/b/h/b;->i:I

    iget-object v14, v5, La/e/b/h/d;->l0:[La/e/b/h/d;

    iget v3, v1, La/e/b/h/b;->o:I

    aput-object v18, v14, v3

    iget-object v14, v5, La/e/b/h/d;->k0:[La/e/b/h/d;

    aput-object v18, v14, v3

    .line 3
    iget v14, v5, La/e/b/h/d;->e0:I

    if-eq v14, v8, :cond_f

    .line 4
    iget v14, v1, La/e/b/h/b;->l:I

    add-int/2addr v14, v4

    iput v14, v1, La/e/b/h/b;->l:I

    invoke-virtual {v5, v3}, La/e/b/h/d;->k(I)La/e/b/h/d$a;

    move-result-object v3

    if-eq v3, v12, :cond_3

    iget v3, v1, La/e/b/h/b;->m:I

    iget v14, v1, La/e/b/h/b;->o:I

    if-nez v14, :cond_1

    .line 5
    invoke-virtual {v5}, La/e/b/h/d;->r()I

    move-result v14

    goto :goto_3

    :cond_1
    if-ne v14, v4, :cond_2

    invoke-virtual {v5}, La/e/b/h/d;->l()I

    move-result v14

    goto :goto_3

    :cond_2
    const/4 v14, 0x0

    :goto_3
    add-int/2addr v3, v14

    .line 6
    iput v3, v1, La/e/b/h/b;->m:I

    :cond_3
    iget v3, v1, La/e/b/h/b;->m:I

    iget-object v14, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v14, v14, v2

    invoke-virtual {v14}, La/e/b/h/c;->d()I

    move-result v14

    add-int/2addr v14, v3

    iput v14, v1, La/e/b/h/b;->m:I

    iget-object v3, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v21, v2, 0x1

    aget-object v3, v3, v21

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v14

    iput v3, v1, La/e/b/h/b;->m:I

    iget v3, v1, La/e/b/h/b;->n:I

    iget-object v14, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v14, v14, v2

    invoke-virtual {v14}, La/e/b/h/c;->d()I

    move-result v14

    add-int/2addr v14, v3

    iput v14, v1, La/e/b/h/b;->n:I

    iget-object v3, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v3, v3, v21

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    add-int/2addr v3, v14

    iput v3, v1, La/e/b/h/b;->n:I

    iget-object v3, v1, La/e/b/h/b;->b:La/e/b/h/d;

    if-nez v3, :cond_4

    iput-object v5, v1, La/e/b/h/b;->b:La/e/b/h/d;

    :cond_4
    iput-object v5, v1, La/e/b/h/b;->d:La/e/b/h/d;

    iget-object v3, v5, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    iget v14, v1, La/e/b/h/b;->o:I

    aget-object v3, v3, v14

    if-ne v3, v12, :cond_f

    iget-object v3, v5, La/e/b/h/d;->p:[I

    aget v21, v3, v14

    const/4 v8, 0x3

    if-eqz v21, :cond_5

    aget v4, v3, v14

    if-eq v4, v8, :cond_5

    aget v3, v3, v14

    if-ne v3, v13, :cond_e

    :cond_5
    iget v3, v1, La/e/b/h/b;->j:I

    const/4 v4, 0x1

    add-int/2addr v3, v4

    iput v3, v1, La/e/b/h/b;->j:I

    iget-object v3, v5, La/e/b/h/d;->j0:[F

    iget v4, v1, La/e/b/h/b;->o:I

    aget v14, v3, v4

    const/16 v20, 0x0

    cmpl-float v23, v14, v20

    if-lez v23, :cond_6

    iget v13, v1, La/e/b/h/b;->k:F

    aget v3, v3, v4

    add-float/2addr v13, v3

    iput v13, v1, La/e/b/h/b;->k:F

    :cond_6
    iget v3, v1, La/e/b/h/b;->o:I

    .line 7
    iget v4, v5, La/e/b/h/d;->e0:I

    const/16 v13, 0x8

    if-eq v4, v13, :cond_8

    .line 8
    iget-object v4, v5, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v4, v4, v3

    if-ne v4, v12, :cond_8

    iget-object v4, v5, La/e/b/h/d;->p:[I

    aget v13, v4, v3

    if-eqz v13, :cond_7

    aget v3, v4, v3

    if-ne v3, v8, :cond_8

    :cond_7
    const/4 v3, 0x1

    goto :goto_4

    :cond_8
    const/4 v3, 0x0

    :goto_4
    if-eqz v3, :cond_b

    const/4 v3, 0x0

    cmpg-float v4, v14, v3

    if-gez v4, :cond_9

    const/4 v3, 0x1

    .line 9
    iput-boolean v3, v1, La/e/b/h/b;->q:Z

    goto :goto_5

    :cond_9
    const/4 v3, 0x1

    iput-boolean v3, v1, La/e/b/h/b;->r:Z

    :goto_5
    iget-object v3, v1, La/e/b/h/b;->h:Ljava/util/ArrayList;

    if-nez v3, :cond_a

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    iput-object v3, v1, La/e/b/h/b;->h:Ljava/util/ArrayList;

    :cond_a
    iget-object v3, v1, La/e/b/h/b;->h:Ljava/util/ArrayList;

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_b
    iget-object v3, v1, La/e/b/h/b;->f:La/e/b/h/d;

    if-nez v3, :cond_c

    iput-object v5, v1, La/e/b/h/b;->f:La/e/b/h/d;

    :cond_c
    iget-object v3, v1, La/e/b/h/b;->g:La/e/b/h/d;

    if-eqz v3, :cond_d

    iget-object v3, v3, La/e/b/h/d;->k0:[La/e/b/h/d;

    iget v4, v1, La/e/b/h/b;->o:I

    aput-object v5, v3, v4

    :cond_d
    iput-object v5, v1, La/e/b/h/b;->g:La/e/b/h/d;

    :cond_e
    iget v3, v1, La/e/b/h/b;->o:I

    :cond_f
    if-eq v6, v5, :cond_10

    iget-object v3, v6, La/e/b/h/d;->l0:[La/e/b/h/d;

    iget v4, v1, La/e/b/h/b;->o:I

    aput-object v5, v3, v4

    :cond_10
    iget-object v3, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v4, v2, 0x1

    aget-object v3, v3, v4

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_11

    iget-object v3, v3, La/e/b/h/c;->d:La/e/b/h/d;

    iget-object v4, v3, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v4, v2

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_11

    aget-object v4, v4, v2

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v4, v4, La/e/b/h/c;->d:La/e/b/h/d;

    if-eq v4, v5, :cond_12

    :cond_11
    move-object/from16 v3, v18

    :cond_12
    if-eqz v3, :cond_13

    goto :goto_6

    :cond_13
    move-object v3, v5

    const/4 v7, 0x1

    :goto_6
    move-object v6, v5

    const/4 v4, 0x1

    const/16 v8, 0x8

    const/4 v13, 0x2

    move-object v5, v3

    goto/16 :goto_2

    :cond_14
    iget-object v3, v1, La/e/b/h/b;->b:La/e/b/h/d;

    if-eqz v3, :cond_15

    iget v4, v1, La/e/b/h/b;->m:I

    iget-object v3, v3, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v3, v3, v2

    invoke-virtual {v3}, La/e/b/h/c;->d()I

    move-result v3

    sub-int/2addr v4, v3

    iput v4, v1, La/e/b/h/b;->m:I

    :cond_15
    iget-object v3, v1, La/e/b/h/b;->d:La/e/b/h/d;

    if-eqz v3, :cond_16

    iget v4, v1, La/e/b/h/b;->m:I

    iget-object v3, v3, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v2, v2, 0x1

    aget-object v2, v3, v2

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    sub-int/2addr v4, v2

    iput v4, v1, La/e/b/h/b;->m:I

    :cond_16
    iput-object v5, v1, La/e/b/h/b;->c:La/e/b/h/d;

    iget v2, v1, La/e/b/h/b;->o:I

    if-nez v2, :cond_17

    iget-boolean v2, v1, La/e/b/h/b;->p:Z

    if-eqz v2, :cond_17

    iput-object v5, v1, La/e/b/h/b;->e:La/e/b/h/d;

    goto :goto_7

    :cond_17
    iget-object v2, v1, La/e/b/h/b;->a:La/e/b/h/d;

    iput-object v2, v1, La/e/b/h/b;->e:La/e/b/h/d;

    :goto_7
    iget-boolean v2, v1, La/e/b/h/b;->r:Z

    if-eqz v2, :cond_18

    iget-boolean v2, v1, La/e/b/h/b;->q:Z

    if-eqz v2, :cond_18

    const/4 v2, 0x1

    goto :goto_8

    :cond_18
    const/4 v2, 0x0

    :goto_8
    iput-boolean v2, v1, La/e/b/h/b;->s:Z

    const/4 v2, 0x1

    goto :goto_9

    :cond_19
    move v2, v4

    .line 10
    :goto_9
    iput-boolean v2, v1, La/e/b/h/b;->t:Z

    if-eqz v11, :cond_1b

    .line 11
    iget-object v2, v1, La/e/b/h/b;->a:La/e/b/h/d;

    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1a

    goto :goto_a

    :cond_1a
    move/from16 v27, v9

    move-object/from16 v19, v12

    move/from16 v29, v15

    const/16 v20, 0x2

    goto/16 :goto_47

    .line 12
    :cond_1b
    :goto_a
    iget-object v13, v1, La/e/b/h/b;->a:La/e/b/h/d;

    iget-object v14, v1, La/e/b/h/b;->c:La/e/b/h/d;

    iget-object v8, v1, La/e/b/h/b;->b:La/e/b/h/d;

    iget-object v7, v1, La/e/b/h/b;->d:La/e/b/h/d;

    iget-object v2, v1, La/e/b/h/b;->e:La/e/b/h/d;

    iget v3, v1, La/e/b/h/b;->k:F

    iget-object v4, v0, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v4, v4, p3

    sget-object v5, La/e/b/h/d$a;->c:La/e/b/h/d$a;

    if-ne v4, v5, :cond_1c

    const/4 v4, 0x1

    goto :goto_b

    :cond_1c
    const/4 v4, 0x0

    :goto_b
    if-nez p3, :cond_20

    iget v5, v2, La/e/b/h/d;->h0:I

    if-nez v5, :cond_1d

    const/4 v5, 0x1

    goto :goto_c

    :cond_1d
    const/4 v5, 0x0

    :goto_c
    iget v6, v2, La/e/b/h/d;->h0:I

    move/from16 v24, v3

    const/4 v3, 0x1

    if-ne v6, v3, :cond_1e

    const/4 v3, 0x1

    goto :goto_d

    :cond_1e
    const/4 v3, 0x0

    :goto_d
    iget v6, v2, La/e/b/h/d;->h0:I

    move/from16 v25, v3

    const/4 v3, 0x2

    move/from16 v36, v9

    move v9, v3

    if-ne v6, v3, :cond_1f

    move/from16 v3, v25

    move/from16 v25, v36

    goto :goto_10

    :cond_1f
    move/from16 v3, v25

    move/from16 v25, v36

    goto :goto_11

    :cond_20
    move/from16 v24, v3

    iget v3, v2, La/e/b/h/d;->i0:I

    if-nez v3, :cond_21

    const/4 v3, 0x1

    goto :goto_e

    :cond_21
    const/4 v3, 0x0

    :goto_e
    iget v5, v2, La/e/b/h/d;->i0:I

    const/4 v6, 0x1

    if-ne v5, v6, :cond_22

    const/4 v5, 0x1

    goto :goto_f

    :cond_22
    const/4 v5, 0x0

    :goto_f
    iget v6, v2, La/e/b/h/d;->i0:I

    move/from16 v25, v9

    const/4 v9, 0x2

    move/from16 v36, v5

    move v5, v3

    move/from16 v3, v36

    if-ne v6, v9, :cond_23

    :goto_10
    move/from16 v23, v3

    move/from16 v26, v5

    const/4 v3, 0x1

    goto :goto_12

    :cond_23
    :goto_11
    move/from16 v23, v3

    move/from16 v26, v5

    const/4 v3, 0x0

    :goto_12
    move-object v6, v13

    const/4 v5, 0x0

    :goto_13
    if-nez v5, :cond_30

    iget-object v9, v6, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v9, v9, v17

    if-eqz v3, :cond_24

    const/16 v28, 0x1

    goto :goto_14

    :cond_24
    const/16 v28, 0x4

    :goto_14
    invoke-virtual {v9}, La/e/b/h/c;->d()I

    move-result v29

    move/from16 v30, v5

    iget-object v5, v6, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v5, v5, p3

    if-ne v5, v12, :cond_25

    iget-object v5, v6, La/e/b/h/d;->p:[I

    aget v5, v5, p3

    if-nez v5, :cond_25

    const/4 v5, 0x1

    goto :goto_15

    :cond_25
    const/4 v5, 0x0

    :goto_15
    iget-object v11, v9, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v11, :cond_26

    if-eq v6, v13, :cond_26

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v11

    add-int v29, v11, v29

    :cond_26
    move/from16 v11, v29

    if-eqz v3, :cond_27

    if-eq v6, v13, :cond_27

    if-eq v6, v8, :cond_27

    move/from16 v29, v15

    const/16 v28, 0x8

    goto :goto_16

    :cond_27
    move/from16 v29, v15

    :goto_16
    iget-object v15, v9, La/e/b/h/c;->f:La/e/b/h/c;

    move-object/from16 v31, v2

    if-eqz v15, :cond_2a

    if-ne v6, v8, :cond_28

    iget-object v2, v9, La/e/b/h/c;->i:La/e/b/g;

    iget-object v15, v15, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v32, v13

    const/4 v13, 0x6

    invoke-virtual {v10, v2, v15, v11, v13}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_17

    :cond_28
    move-object/from16 v32, v13

    iget-object v2, v9, La/e/b/h/c;->i:La/e/b/g;

    iget-object v13, v15, La/e/b/h/c;->i:La/e/b/g;

    const/16 v15, 0x8

    invoke-virtual {v10, v2, v13, v11, v15}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :goto_17
    if-eqz v5, :cond_29

    if-nez v3, :cond_29

    const/4 v2, 0x5

    goto :goto_18

    :cond_29
    move/from16 v2, v28

    :goto_18
    iget-object v5, v9, La/e/b/h/c;->i:La/e/b/g;

    iget-object v9, v9, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v9, v9, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v10, v5, v9, v11, v2}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_19

    :cond_2a
    move-object/from16 v32, v13

    :goto_19
    if-eqz v4, :cond_2c

    .line 13
    iget v2, v6, La/e/b/h/d;->e0:I

    const/16 v5, 0x8

    if-eq v2, v5, :cond_2b

    .line 14
    iget-object v2, v6, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v2, v2, p3

    if-ne v2, v12, :cond_2b

    iget-object v2, v6, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v5, v17, 0x1

    aget-object v5, v2, v5

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    aget-object v2, v2, v17

    iget-object v2, v2, La/e/b/h/c;->i:La/e/b/g;

    const/4 v9, 0x5

    const/4 v11, 0x0

    invoke-virtual {v10, v5, v2, v11, v9}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    goto :goto_1a

    :cond_2b
    const/4 v11, 0x0

    :goto_1a
    iget-object v2, v6, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v17

    iget-object v2, v2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v5, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v5, v5, v17

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    const/16 v9, 0x8

    invoke-virtual {v10, v2, v5, v11, v9}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_2c
    iget-object v2, v6, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v5, v17, 0x1

    aget-object v2, v2, v5

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v2, :cond_2d

    iget-object v2, v2, La/e/b/h/c;->d:La/e/b/h/d;

    iget-object v5, v2, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v9, v5, v17

    iget-object v9, v9, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v9, :cond_2d

    aget-object v5, v5, v17

    iget-object v5, v5, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v5, v5, La/e/b/h/c;->d:La/e/b/h/d;

    if-eq v5, v6, :cond_2e

    :cond_2d
    move-object/from16 v2, v18

    :cond_2e
    if-eqz v2, :cond_2f

    move-object v6, v2

    move/from16 v5, v30

    goto :goto_1b

    :cond_2f
    const/4 v5, 0x1

    :goto_1b
    move-object/from16 v11, p2

    move/from16 v15, v29

    move-object/from16 v2, v31

    move-object/from16 v13, v32

    goto/16 :goto_13

    :cond_30
    move-object/from16 v31, v2

    move-object/from16 v32, v13

    move/from16 v29, v15

    if-eqz v7, :cond_34

    iget-object v2, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v5, v17, 0x1

    aget-object v2, v2, v5

    iget-object v2, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v2, :cond_34

    iget-object v2, v7, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v5

    iget-object v6, v7, La/e/b/h/d;->Q:[La/e/b/h/d$a;

    aget-object v6, v6, p3

    if-ne v6, v12, :cond_31

    iget-object v6, v7, La/e/b/h/d;->p:[I

    aget v6, v6, p3

    if-nez v6, :cond_31

    const/4 v6, 0x1

    goto :goto_1c

    :cond_31
    const/4 v6, 0x0

    :goto_1c
    if-eqz v6, :cond_32

    if-nez v3, :cond_32

    iget-object v6, v2, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v9, v6, La/e/b/h/c;->d:La/e/b/h/d;

    if-ne v9, v0, :cond_32

    iget-object v9, v2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v6, v6, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v11

    neg-int v11, v11

    const/4 v13, 0x5

    invoke-virtual {v10, v9, v6, v11, v13}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_1d

    :cond_32
    const/4 v13, 0x5

    if-eqz v3, :cond_33

    iget-object v6, v2, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v9, v6, La/e/b/h/c;->d:La/e/b/h/d;

    if-ne v9, v0, :cond_33

    iget-object v9, v2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v6, v6, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v11

    neg-int v11, v11

    const/4 v15, 0x4

    invoke-virtual {v10, v9, v6, v11, v15}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_1e

    :cond_33
    :goto_1d
    const/4 v15, 0x4

    :goto_1e
    iget-object v6, v2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v9, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v5, v9, v5

    iget-object v5, v5, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    const/4 v9, 0x6

    invoke-virtual {v10, v6, v5, v2, v9}, La/e/b/d;->g(La/e/b/g;La/e/b/g;II)V

    goto :goto_1f

    :cond_34
    const/4 v13, 0x5

    const/4 v15, 0x4

    :goto_1f
    if-eqz v4, :cond_35

    iget-object v2, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v4, v17, 0x1

    aget-object v2, v2, v4

    iget-object v2, v2, La/e/b/h/c;->i:La/e/b/g;

    iget-object v5, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v5, v4

    iget-object v6, v6, La/e/b/h/c;->i:La/e/b/g;

    aget-object v4, v5, v4

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    const/16 v5, 0x8

    invoke-virtual {v10, v2, v6, v4, v5}, La/e/b/d;->f(La/e/b/g;La/e/b/g;II)V

    :cond_35
    iget-object v2, v1, La/e/b/h/b;->h:Ljava/util/ArrayList;

    if-eqz v2, :cond_3f

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v4

    const/4 v5, 0x1

    if-le v4, v5, :cond_3f

    iget-boolean v6, v1, La/e/b/h/b;->q:Z

    if-eqz v6, :cond_36

    iget-boolean v6, v1, La/e/b/h/b;->s:Z

    if-nez v6, :cond_36

    iget v6, v1, La/e/b/h/b;->j:I

    int-to-float v6, v6

    goto :goto_20

    :cond_36
    move/from16 v6, v24

    :goto_20
    move-object/from16 v5, v18

    const/4 v9, 0x0

    const/4 v11, 0x0

    :goto_21
    if-ge v11, v4, :cond_3f

    invoke-virtual {v2, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v24

    move-object/from16 v13, v24

    check-cast v13, La/e/b/h/d;

    iget-object v15, v13, La/e/b/h/d;->j0:[F

    aget v15, v15, p3

    const/16 v20, 0x0

    cmpg-float v24, v15, v20

    if-gez v24, :cond_38

    iget-boolean v15, v1, La/e/b/h/b;->s:Z

    if-eqz v15, :cond_37

    iget-object v0, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v13, v17, 0x1

    aget-object v13, v0, v13

    iget-object v13, v13, La/e/b/h/c;->i:La/e/b/g;

    aget-object v0, v0, v17

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v19, v12

    const/4 v12, 0x0

    const/4 v15, 0x4

    goto :goto_22

    :cond_37
    const/high16 v15, 0x3f800000    # 1.0f

    :cond_38
    const/16 v20, 0x0

    cmpl-float v24, v15, v20

    if-nez v24, :cond_39

    iget-object v0, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v13, v17, 0x1

    aget-object v13, v0, v13

    iget-object v13, v13, La/e/b/h/c;->i:La/e/b/g;

    aget-object v0, v0, v17

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v19, v12

    const/4 v12, 0x0

    const/16 v15, 0x8

    :goto_22
    invoke-virtual {v10, v13, v0, v12, v15}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    move-object/from16 v33, v2

    move/from16 v30, v4

    move/from16 v24, v6

    const/16 v20, 0x0

    goto/16 :goto_27

    :cond_39
    move-object/from16 v19, v12

    const/4 v12, 0x0

    if-eqz v5, :cond_3e

    iget-object v5, v5, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v12, v5, v17

    iget-object v12, v12, La/e/b/h/c;->i:La/e/b/g;

    add-int/lit8 v30, v17, 0x1

    aget-object v5, v5, v30

    iget-object v5, v5, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    move-object/from16 v33, v2

    aget-object v2, v0, v17

    iget-object v2, v2, La/e/b/h/c;->i:La/e/b/g;

    aget-object v0, v0, v30

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    move/from16 v30, v4

    invoke-virtual/range {p1 .. p1}, La/e/b/d;->m()La/e/b/b;

    move-result-object v4

    move-object/from16 v34, v13

    const/4 v13, 0x0

    .line 15
    iput v13, v4, La/e/b/b;->b:F

    cmpl-float v20, v6, v13

    const/high16 v13, -0x40800000    # -1.0f

    if-eqz v20, :cond_3d

    cmpl-float v20, v9, v15

    if-nez v20, :cond_3a

    goto :goto_24

    :cond_3a
    const/16 v20, 0x0

    cmpl-float v35, v9, v20

    if-nez v35, :cond_3b

    iget-object v0, v4, La/e/b/b;->e:La/e/b/b$a;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-interface {v0, v12, v2}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v0, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v0, v5, v13}, La/e/b/b$a;->j(La/e/b/g;F)V

    goto :goto_23

    :cond_3b
    const/high16 v13, 0x3f800000    # 1.0f

    if-nez v24, :cond_3c

    iget-object v5, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v5, v2, v13}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v2, v4, La/e/b/b;->e:La/e/b/b$a;

    const/high16 v5, -0x40800000    # -1.0f

    invoke-interface {v2, v0, v5}, La/e/b/b$a;->j(La/e/b/g;F)V

    :goto_23
    move/from16 v24, v6

    goto :goto_25

    :cond_3c
    div-float/2addr v9, v6

    div-float v24, v15, v6

    div-float v9, v9, v24

    move/from16 v24, v6

    iget-object v6, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v6, v12, v13}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v6, v4, La/e/b/b;->e:La/e/b/b$a;

    const/high16 v12, -0x40800000    # -1.0f

    invoke-interface {v6, v5, v12}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v5, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v5, v0, v9}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v0, v4, La/e/b/b;->e:La/e/b/b$a;

    neg-float v5, v9

    invoke-interface {v0, v2, v5}, La/e/b/b$a;->j(La/e/b/g;F)V

    goto :goto_25

    :cond_3d
    :goto_24
    move/from16 v24, v6

    move v6, v13

    const/high16 v13, 0x3f800000    # 1.0f

    const/16 v20, 0x0

    iget-object v9, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v9, v12, v13}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v9, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v9, v5, v6}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v5, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v5, v0, v13}, La/e/b/b$a;->j(La/e/b/g;F)V

    iget-object v0, v4, La/e/b/b;->e:La/e/b/b$a;

    invoke-interface {v0, v2, v6}, La/e/b/b$a;->j(La/e/b/g;F)V

    .line 16
    :goto_25
    invoke-virtual {v10, v4}, La/e/b/d;->c(La/e/b/b;)V

    goto :goto_26

    :cond_3e
    move-object/from16 v33, v2

    move/from16 v30, v4

    move/from16 v24, v6

    move-object/from16 v34, v13

    const/16 v20, 0x0

    :goto_26
    move v9, v15

    move-object/from16 v5, v34

    :goto_27
    add-int/lit8 v11, v11, 0x1

    const/4 v13, 0x5

    const/4 v15, 0x4

    move-object/from16 v0, p0

    move-object/from16 v12, v19

    move/from16 v6, v24

    move/from16 v4, v30

    move-object/from16 v2, v33

    goto/16 :goto_21

    :cond_3f
    move-object/from16 v19, v12

    if-eqz v8, :cond_46

    if-eq v8, v7, :cond_40

    if-eqz v3, :cond_46

    :cond_40
    move-object/from16 v0, v32

    iget-object v0, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v17

    iget-object v1, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v2, v17, 0x1

    aget-object v1, v1, v2

    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_41

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    move-object v3, v0

    goto :goto_28

    :cond_41
    move-object/from16 v3, v18

    :goto_28
    iget-object v0, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_42

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    move-object v6, v0

    goto :goto_29

    :cond_42
    move-object/from16 v6, v18

    :goto_29
    iget-object v0, v8, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v17

    iget-object v1, v7, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v2

    if-eqz v3, :cond_44

    if-eqz v6, :cond_44

    move-object/from16 v2, v31

    if-nez p3, :cond_43

    iget v2, v2, La/e/b/h/d;->b0:F

    goto :goto_2a

    :cond_43
    iget v2, v2, La/e/b/h/d;->c0:F

    :goto_2a
    move v5, v2

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v4

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v9

    iget-object v2, v0, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, v1, La/e/b/h/c;->i:La/e/b/g;

    const/4 v11, 0x7

    move-object/from16 v1, p1

    move-object v12, v7

    move-object v7, v0

    move-object v13, v8

    move v8, v9

    move/from16 v15, v25

    const/16 v20, 0x2

    move v9, v11

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    goto :goto_2b

    :cond_44
    move-object v12, v7

    move-object v13, v8

    move/from16 v15, v25

    const/16 v20, 0x2

    :cond_45
    :goto_2b
    move/from16 v27, v15

    goto/16 :goto_43

    :cond_46
    move-object v12, v7

    move-object v13, v8

    move/from16 v15, v25

    move-object/from16 v0, v32

    const/16 v20, 0x2

    if-eqz v26, :cond_58

    if-eqz v13, :cond_58

    iget v2, v1, La/e/b/h/b;->j:I

    if-lez v2, :cond_47

    iget v1, v1, La/e/b/h/b;->i:I

    if-ne v1, v2, :cond_47

    const/16 v21, 0x1

    goto :goto_2c

    :cond_47
    const/16 v21, 0x0

    :goto_2c
    move-object v9, v13

    move-object v11, v9

    :goto_2d
    if-eqz v11, :cond_45

    iget-object v1, v11, La/e/b/h/d;->l0:[La/e/b/h/d;

    aget-object v1, v1, p3

    move-object v8, v1

    :goto_2e
    if-eqz v8, :cond_48

    .line 17
    iget v1, v8, La/e/b/h/d;->e0:I

    const/16 v7, 0x8

    if-ne v1, v7, :cond_49

    .line 18
    iget-object v1, v8, La/e/b/h/d;->l0:[La/e/b/h/d;

    aget-object v8, v1, p3

    goto :goto_2e

    :cond_48
    const/16 v7, 0x8

    :cond_49
    if-nez v8, :cond_4b

    if-ne v11, v12, :cond_4a

    goto :goto_2f

    :cond_4a
    move-object/from16 v22, v8

    move-object/from16 v24, v9

    move/from16 v27, v15

    const/4 v15, 0x5

    goto/16 :goto_36

    :cond_4b
    :goto_2f
    iget-object v1, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v17

    iget-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v3, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_4c

    iget-object v3, v3, La/e/b/h/c;->i:La/e/b/g;

    goto :goto_30

    :cond_4c
    move-object/from16 v3, v18

    :goto_30
    if-eq v9, v11, :cond_4d

    iget-object v3, v9, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v4, v17, 0x1

    aget-object v3, v3, v4

    goto :goto_31

    :cond_4d
    if-ne v11, v13, :cond_4f

    if-ne v9, v11, :cond_4f

    iget-object v3, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v4, v3, v17

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_4e

    aget-object v3, v3, v17

    iget-object v3, v3, La/e/b/h/c;->f:La/e/b/h/c;

    :goto_31
    iget-object v3, v3, La/e/b/h/c;->i:La/e/b/g;

    goto :goto_32

    :cond_4e
    move-object/from16 v3, v18

    :cond_4f
    :goto_32
    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    iget-object v4, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v5, v17, 0x1

    aget-object v4, v4, v5

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    if-eqz v8, :cond_50

    iget-object v6, v8, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v17

    iget-object v7, v6, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v24, v6

    iget-object v6, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v5

    goto :goto_34

    :cond_50
    iget-object v6, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v5

    iget-object v6, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v6, :cond_51

    iget-object v7, v6, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v24, v6

    goto :goto_33

    :cond_51
    move-object/from16 v24, v6

    move-object/from16 v7, v18

    :goto_33
    iget-object v6, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v5

    :goto_34
    iget-object v6, v6, La/e/b/h/c;->i:La/e/b/g;

    if-eqz v24, :cond_52

    invoke-virtual/range {v24 .. v24}, La/e/b/h/c;->d()I

    move-result v24

    add-int v4, v4, v24

    :cond_52
    move/from16 v24, v4

    if-eqz v9, :cond_53

    iget-object v4, v9, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v4, v4, v5

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    add-int/2addr v1, v4

    :cond_53
    if-eqz v2, :cond_4a

    if-eqz v3, :cond_4a

    if-eqz v7, :cond_4a

    if-eqz v6, :cond_4a

    if-ne v11, v13, :cond_54

    iget-object v1, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v17

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    :cond_54
    move v4, v1

    if-ne v11, v12, :cond_55

    iget-object v1, v12, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v5

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    move/from16 v24, v1

    :cond_55
    if-eqz v21, :cond_56

    const/16 v25, 0x8

    goto :goto_35

    :cond_56
    const/16 v25, 0x5

    :goto_35
    const/high16 v5, 0x3f000000    # 0.5f

    move-object/from16 v1, p1

    move-object/from16 v27, v6

    move-object v6, v7

    const/16 v22, 0x8

    move-object/from16 v7, v27

    move-object/from16 v22, v8

    move/from16 v8, v24

    move-object/from16 v24, v9

    move/from16 v27, v15

    const/4 v15, 0x5

    move/from16 v9, v25

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    .line 19
    :goto_36
    iget v1, v11, La/e/b/h/d;->e0:I

    const/16 v9, 0x8

    if-eq v1, v9, :cond_57

    move-object/from16 v24, v11

    :cond_57
    move-object/from16 v11, v22

    move-object/from16 v9, v24

    move/from16 v15, v27

    goto/16 :goto_2d

    :cond_58
    move/from16 v27, v15

    const/16 v9, 0x8

    const/4 v15, 0x5

    if-eqz v23, :cond_67

    if-eqz v13, :cond_67

    .line 20
    iget v2, v1, La/e/b/h/b;->j:I

    if-lez v2, :cond_59

    iget v1, v1, La/e/b/h/b;->i:I

    if-ne v1, v2, :cond_59

    const/16 v21, 0x1

    goto :goto_37

    :cond_59
    const/16 v21, 0x0

    :goto_37
    move-object v8, v13

    move-object v11, v8

    :goto_38
    if-eqz v11, :cond_64

    iget-object v1, v11, La/e/b/h/d;->l0:[La/e/b/h/d;

    aget-object v1, v1, p3

    :goto_39
    if-eqz v1, :cond_5a

    .line 21
    iget v2, v1, La/e/b/h/d;->e0:I

    if-ne v2, v9, :cond_5a

    .line 22
    iget-object v1, v1, La/e/b/h/d;->l0:[La/e/b/h/d;

    aget-object v1, v1, p3

    goto :goto_39

    :cond_5a
    if-eq v11, v13, :cond_62

    if-eq v11, v12, :cond_62

    if-eqz v1, :cond_62

    if-ne v1, v12, :cond_5b

    move-object/from16 v7, v18

    goto :goto_3a

    :cond_5b
    move-object v7, v1

    :goto_3a
    iget-object v1, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v17

    iget-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v3, v8, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v4, v17, 0x1

    aget-object v3, v3, v4

    iget-object v3, v3, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    iget-object v5, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v5, v5, v4

    invoke-virtual {v5}, La/e/b/h/c;->d()I

    move-result v5

    if-eqz v7, :cond_5d

    iget-object v6, v7, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v17

    iget-object v9, v6, La/e/b/h/c;->i:La/e/b/g;

    iget-object v15, v6, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v15, :cond_5c

    goto :goto_3c

    :cond_5c
    move-object/from16 v15, v18

    goto :goto_3d

    :cond_5d
    iget-object v6, v12, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v6, v6, v17

    if-eqz v6, :cond_5e

    iget-object v9, v6, La/e/b/h/c;->i:La/e/b/g;

    goto :goto_3b

    :cond_5e
    move-object/from16 v9, v18

    :goto_3b
    iget-object v15, v11, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v15, v15, v4

    :goto_3c
    iget-object v15, v15, La/e/b/h/c;->i:La/e/b/g;

    :goto_3d
    if-eqz v6, :cond_5f

    invoke-virtual {v6}, La/e/b/h/c;->d()I

    move-result v6

    add-int/2addr v6, v5

    move/from16 v22, v6

    goto :goto_3e

    :cond_5f
    move/from16 v22, v5

    :goto_3e
    iget-object v5, v8, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v4, v5, v4

    invoke-virtual {v4}, La/e/b/h/c;->d()I

    move-result v4

    add-int/2addr v4, v1

    if-eqz v21, :cond_60

    const/16 v24, 0x8

    goto :goto_3f

    :cond_60
    const/16 v24, 0x4

    :goto_3f
    if-eqz v2, :cond_61

    if-eqz v3, :cond_61

    if-eqz v9, :cond_61

    if-eqz v15, :cond_61

    const/high16 v5, 0x3f000000    # 0.5f

    move-object/from16 v1, p1

    move-object v6, v9

    move-object/from16 v25, v7

    move-object v7, v15

    move-object v15, v8

    move/from16 v8, v22

    move-object/from16 v28, v15

    const/16 v15, 0x8

    const/16 v22, 0x4

    move/from16 v9, v24

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    goto :goto_40

    :cond_61
    move-object/from16 v25, v7

    move-object/from16 v28, v8

    const/16 v15, 0x8

    const/16 v22, 0x4

    :goto_40
    move-object/from16 v8, v25

    goto :goto_41

    :cond_62
    move-object/from16 v28, v8

    move v15, v9

    const/16 v22, 0x4

    move-object v8, v1

    .line 23
    :goto_41
    iget v1, v11, La/e/b/h/d;->e0:I

    if-eq v1, v15, :cond_63

    move-object/from16 v28, v11

    :cond_63
    move-object v11, v8

    move v9, v15

    move-object/from16 v8, v28

    const/4 v15, 0x5

    goto/16 :goto_38

    .line 24
    :cond_64
    iget-object v1, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v1, v17

    iget-object v0, v0, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v17

    iget-object v0, v0, La/e/b/h/c;->f:La/e/b/h/c;

    iget-object v2, v12, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v3, v17, 0x1

    aget-object v11, v2, v3

    iget-object v2, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v2, v3

    iget-object v15, v2, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v0, :cond_66

    if-eq v13, v12, :cond_65

    iget-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v0, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v1

    const/4 v3, 0x5

    invoke-virtual {v10, v2, v0, v1, v3}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    goto :goto_42

    :cond_65
    if-eqz v15, :cond_66

    iget-object v2, v1, La/e/b/h/c;->i:La/e/b/g;

    iget-object v3, v0, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v1}, La/e/b/h/c;->d()I

    move-result v4

    const/high16 v5, 0x3f000000    # 0.5f

    iget-object v6, v11, La/e/b/h/c;->i:La/e/b/g;

    iget-object v7, v15, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v8

    const/4 v9, 0x5

    move-object/from16 v1, p1

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    :cond_66
    :goto_42
    if-eqz v15, :cond_67

    if-eq v13, v12, :cond_67

    iget-object v0, v11, La/e/b/h/c;->i:La/e/b/g;

    iget-object v1, v15, La/e/b/h/c;->i:La/e/b/g;

    invoke-virtual {v11}, La/e/b/h/c;->d()I

    move-result v2

    neg-int v2, v2

    const/4 v3, 0x5

    invoke-virtual {v10, v0, v1, v2, v3}, La/e/b/d;->d(La/e/b/g;La/e/b/g;II)La/e/b/b;

    :cond_67
    :goto_43
    if-nez v26, :cond_68

    if-eqz v23, :cond_6e

    :cond_68
    if-eqz v13, :cond_6e

    if-eq v13, v12, :cond_6e

    iget-object v0, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v0, v0, v17

    iget-object v1, v12, La/e/b/h/d;->N:[La/e/b/h/c;

    add-int/lit8 v2, v17, 0x1

    aget-object v1, v1, v2

    iget-object v3, v0, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v3, :cond_69

    iget-object v3, v3, La/e/b/h/c;->i:La/e/b/g;

    goto :goto_44

    :cond_69
    move-object/from16 v3, v18

    :goto_44
    iget-object v4, v1, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_6a

    iget-object v4, v4, La/e/b/h/c;->i:La/e/b/g;

    goto :goto_45

    :cond_6a
    move-object/from16 v4, v18

    :goto_45
    if-eq v14, v12, :cond_6c

    iget-object v4, v14, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v4, v4, v2

    iget-object v4, v4, La/e/b/h/c;->f:La/e/b/h/c;

    if-eqz v4, :cond_6b

    iget-object v4, v4, La/e/b/h/c;->i:La/e/b/g;

    move-object/from16 v18, v4

    :cond_6b
    move-object/from16 v6, v18

    goto :goto_46

    :cond_6c
    move-object v6, v4

    :goto_46
    if-ne v13, v12, :cond_6d

    iget-object v0, v13, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v1, v0, v17

    aget-object v0, v0, v2

    move-object/from16 v36, v1

    move-object v1, v0

    move-object/from16 v0, v36

    :cond_6d
    if-eqz v3, :cond_6e

    if-eqz v6, :cond_6e

    const/high16 v5, 0x3f000000    # 0.5f

    invoke-virtual {v0}, La/e/b/h/c;->d()I

    move-result v4

    iget-object v7, v12, La/e/b/h/d;->N:[La/e/b/h/c;

    aget-object v2, v7, v2

    invoke-virtual {v2}, La/e/b/h/c;->d()I

    move-result v8

    iget-object v2, v0, La/e/b/h/c;->i:La/e/b/g;

    iget-object v7, v1, La/e/b/h/c;->i:La/e/b/g;

    const/4 v9, 0x5

    move-object/from16 v1, p1

    invoke-virtual/range {v1 .. v9}, La/e/b/d;->b(La/e/b/g;La/e/b/g;IFLa/e/b/g;La/e/b/g;II)V

    :cond_6e
    :goto_47
    add-int/lit8 v9, v27, 0x1

    move-object/from16 v0, p0

    move-object/from16 v11, p2

    move-object/from16 v12, v19

    move/from16 v13, v20

    move/from16 v15, v29

    goto/16 :goto_1

    :cond_6f
    return-void
.end method

.method public static b(Ljava/lang/Object;Ljava/lang/StringBuilder;)V
    .locals 2

    if-nez p0, :cond_0

    const-string p0, "null"

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    if-gtz v1, :cond_1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0x2e

    invoke-virtual {v0, v1}, Ljava/lang/String;->lastIndexOf(I)I

    move-result v1

    if-lez v1, :cond_1

    add-int/lit8 v1, v1, 0x1

    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    :cond_1
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v0, 0x7b

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object p0

    :goto_0
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-void
.end method

.method public static c(I)I
    .locals 0

    if-ltz p0, :cond_0

    return p0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw p0
.end method

.method public static d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(TT;",
            "Ljava/lang/Object;",
            ")TT;"
        }
    .end annotation

    if-eqz p0, :cond_0

    return-object p0

    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static e(Landroid/content/Context;Ljava/lang/String;)I
    .locals 4

    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {}, Landroid/os/Process;->myUid()I

    move-result v1

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v2

    .line 1
    invoke-virtual {p0, p1, v0, v1}, Landroid/content/Context;->checkPermission(Ljava/lang/String;II)I

    move-result v0

    const/4 v3, -0x1

    if-ne v0, v3, :cond_0

    goto :goto_1

    .line 2
    :cond_0
    invoke-static {p1}, Landroid/app/AppOpsManager;->permissionToOp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    if-nez v2, :cond_3

    .line 3
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v2

    invoke-virtual {v2, v1}, Landroid/content/pm/PackageManager;->getPackagesForUid(I)[Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_5

    array-length v2, v1

    if-gtz v2, :cond_2

    goto :goto_1

    :cond_2
    aget-object v2, v1, v0

    .line 4
    :cond_3
    const-class v1, Landroid/app/AppOpsManager;

    invoke-virtual {p0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/app/AppOpsManager;

    invoke-virtual {p0, p1, v2}, Landroid/app/AppOpsManager;->noteProxyOpNoThrow(Ljava/lang/String;Ljava/lang/String;)I

    move-result p0

    if-eqz p0, :cond_4

    const/4 v3, -0x2

    goto :goto_1

    :cond_4
    :goto_0
    move v3, v0

    :cond_5
    :goto_1
    return v3
.end method

.method public static f(Ljava/io/File;Landroid/content/res/Resources;I)Z
    .locals 0

    :try_start_0
    invoke-virtual {p1, p2}, Landroid/content/res/Resources;->openRawResource(I)Ljava/io/InputStream;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    invoke-static {p0, p1}, La/b/k/h$i;->g(Ljava/io/File;Ljava/io/InputStream;)Z

    move-result p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-eqz p1, :cond_0

    .line 1
    :try_start_2
    invoke-interface {p1}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    :catch_0
    :cond_0
    return p0

    :catchall_0
    move-exception p0

    goto :goto_0

    :catchall_1
    move-exception p0

    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    :try_start_3
    invoke-interface {p1}, Ljava/io/Closeable;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 2
    :catch_1
    :cond_1
    throw p0
.end method

.method public static g(Ljava/io/File;Ljava/io/InputStream;)Z
    .locals 5

    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskWrites()Landroid/os/StrictMode$ThreadPolicy;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    :try_start_0
    new-instance v3, Ljava/io/FileOutputStream;

    invoke-direct {v3, p0, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;Z)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    const/16 p0, 0x400

    :try_start_1
    new-array p0, p0, [B

    :goto_0
    invoke-virtual {p1, p0}, Ljava/io/InputStream;->read([B)I

    move-result v2

    const/4 v4, -0x1

    if-eq v2, v4, :cond_0

    invoke-virtual {v3, p0, v1, v2}, Ljava/io/FileOutputStream;->write([BII)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x1

    .line 1
    :try_start_2
    invoke-virtual {v3}, Ljava/io/FileOutputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 2
    :catch_0
    invoke-static {v0}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    return p0

    :catchall_0
    move-exception p0

    move-object v2, v3

    goto :goto_2

    :catch_1
    move-exception p0

    move-object v2, v3

    goto :goto_1

    :catchall_1
    move-exception p0

    goto :goto_2

    :catch_2
    move-exception p0

    :goto_1
    :try_start_3
    const-string p1, "TypefaceCompatUtil"

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Error copying resource contents to temp file: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/io/IOException;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-eqz v2, :cond_1

    .line 3
    :try_start_4
    invoke-interface {v2}, Ljava/io/Closeable;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3

    .line 4
    :catch_3
    :cond_1
    invoke-static {v0}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    return v1

    :goto_2
    if-eqz v2, :cond_2

    .line 5
    :try_start_5
    invoke-interface {v2}, Ljava/io/Closeable;->close()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_4

    .line 6
    :catch_4
    :cond_2
    invoke-static {v0}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    throw p0
.end method

.method public static h(La/e/b/h/d;ILjava/util/ArrayList;La/e/b/h/l/n;)La/e/b/h/l/n;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "La/e/b/h/d;",
            "I",
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/n;",
            ">;",
            "La/e/b/h/l/n;",
            ")",
            "La/e/b/h/l/n;"
        }
    .end annotation

    if-nez p1, :cond_0

    iget v0, p0, La/e/b/h/d;->m0:I

    goto :goto_0

    :cond_0
    iget v0, p0, La/e/b/h/d;->n0:I

    :goto_0
    const/4 v1, 0x0

    const/4 v2, -0x1

    if-eq v0, v2, :cond_4

    if-eqz p3, :cond_1

    iget v3, p3, La/e/b/h/l/n;->b:I

    if-eq v0, v3, :cond_4

    :cond_1
    move v3, v1

    :goto_1
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-ge v3, v4, :cond_5

    invoke-virtual {p2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, La/e/b/h/l/n;

    .line 1
    iget v5, v4, La/e/b/h/l/n;->b:I

    if-ne v5, v0, :cond_3

    if-eqz p3, :cond_2

    .line 2
    invoke-virtual {p3, p1, v4}, La/e/b/h/l/n;->d(ILa/e/b/h/l/n;)V

    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_2
    move-object p3, v4

    goto :goto_2

    :cond_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_4
    if-eq v0, v2, :cond_5

    return-object p3

    :cond_5
    :goto_2
    const/4 v0, 0x1

    if-nez p3, :cond_c

    instance-of v3, p0, La/e/b/h/h;

    if-eqz v3, :cond_a

    move-object v3, p0

    check-cast v3, La/e/b/h/h;

    move v4, v1

    .line 3
    :goto_3
    iget v5, v3, La/e/b/h/h;->p0:I

    if-ge v4, v5, :cond_8

    iget-object v5, v3, La/e/b/h/h;->o0:[La/e/b/h/d;

    aget-object v5, v5, v4

    if-nez p1, :cond_6

    iget v6, v5, La/e/b/h/d;->m0:I

    if-eq v6, v2, :cond_6

    goto :goto_4

    :cond_6
    if-ne p1, v0, :cond_7

    iget v6, v5, La/e/b/h/d;->n0:I

    if-eq v6, v2, :cond_7

    goto :goto_4

    :cond_7
    add-int/lit8 v4, v4, 0x1

    goto :goto_3

    :cond_8
    move v6, v2

    :goto_4
    if-eq v6, v2, :cond_a

    move v2, v1

    .line 4
    :goto_5
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    move-result v3

    if-ge v2, v3, :cond_a

    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/e/b/h/l/n;

    .line 5
    iget v4, v3, La/e/b/h/l/n;->b:I

    if-ne v4, v6, :cond_9

    move-object p3, v3

    goto :goto_6

    :cond_9
    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    :cond_a
    :goto_6
    if-nez p3, :cond_b

    .line 6
    new-instance p3, La/e/b/h/l/n;

    invoke-direct {p3, p1}, La/e/b/h/l/n;-><init>(I)V

    :cond_b
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_c
    invoke-virtual {p3, p0}, La/e/b/h/l/n;->a(La/e/b/h/d;)Z

    move-result v2

    if-eqz v2, :cond_10

    instance-of v2, p0, La/e/b/h/f;

    if-eqz v2, :cond_e

    move-object v2, p0

    check-cast v2, La/e/b/h/f;

    .line 7
    iget-object v3, v2, La/e/b/h/f;->r0:La/e/b/h/c;

    .line 8
    iget v2, v2, La/e/b/h/f;->s0:I

    if-nez v2, :cond_d

    move v1, v0

    .line 9
    :cond_d
    invoke-virtual {v3, v1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    :cond_e
    if-nez p1, :cond_f

    .line 10
    iget v0, p3, La/e/b/h/l/n;->b:I

    .line 11
    iput v0, p0, La/e/b/h/d;->m0:I

    iget-object v0, p0, La/e/b/h/d;->F:La/e/b/h/c;

    invoke-virtual {v0, p1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    iget-object v0, p0, La/e/b/h/d;->H:La/e/b/h/c;

    goto :goto_7

    .line 12
    :cond_f
    iget v0, p3, La/e/b/h/l/n;->b:I

    .line 13
    iput v0, p0, La/e/b/h/d;->n0:I

    iget-object v0, p0, La/e/b/h/d;->G:La/e/b/h/c;

    invoke-virtual {v0, p1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    iget-object v0, p0, La/e/b/h/d;->J:La/e/b/h/c;

    invoke-virtual {v0, p1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    iget-object v0, p0, La/e/b/h/d;->I:La/e/b/h/c;

    :goto_7
    invoke-virtual {v0, p1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    iget-object p0, p0, La/e/b/h/d;->M:La/e/b/h/c;

    invoke-virtual {p0, p1, p2, p3}, La/e/b/h/c;->b(ILjava/util/ArrayList;La/e/b/h/l/n;)V

    :cond_10
    return-object p3
.end method

.method public static i(Ljava/util/ArrayList;I)La/e/b/h/l/n;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "La/e/b/h/l/n;",
            ">;I)",
            "La/e/b/h/l/n;"
        }
    .end annotation

    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, La/e/b/h/l/n;

    iget v3, v2, La/e/b/h/l/n;->b:I

    if-ne p1, v3, :cond_0

    return-object v2

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static j(Ljava/lang/Object;)V
    .locals 4

    sget-boolean v0, La/b/k/h$i;->d:Z

    const/4 v1, 0x1

    const-string v2, "ResourcesFlusher"

    if-nez v0, :cond_0

    :try_start_0
    const-string v0, "android.content.res.ThemedResourceCache"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    sput-object v0, La/b/k/h$i;->c:Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    const-string v3, "Could not find ThemedResourceCache class"

    invoke-static {v2, v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_0
    sput-boolean v1, La/b/k/h$i;->d:Z

    :cond_0
    sget-object v0, La/b/k/h$i;->c:Ljava/lang/Class;

    if-nez v0, :cond_1

    return-void

    :cond_1
    sget-boolean v3, La/b/k/h$i;->f:Z

    if-nez v3, :cond_2

    :try_start_1
    const-string v3, "mUnthemedEntries"

    invoke-virtual {v0, v3}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v0

    sput-object v0, La/b/k/h$i;->e:Ljava/lang/reflect/Field;

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    :try_end_1
    .catch Ljava/lang/NoSuchFieldException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    :catch_1
    move-exception v0

    const-string v3, "Could not retrieve ThemedResourceCache#mUnthemedEntries field"

    invoke-static {v2, v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_1
    sput-boolean v1, La/b/k/h$i;->f:Z

    :cond_2
    sget-object v0, La/b/k/h$i;->e:Ljava/lang/reflect/Field;

    if-nez v0, :cond_3

    return-void

    :cond_3
    const/4 v1, 0x0

    :try_start_2
    invoke-virtual {v0, p0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/util/LongSparseArray;
    :try_end_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_2 .. :try_end_2} :catch_2

    move-object v1, p0

    goto :goto_2

    :catch_2
    move-exception p0

    const-string v0, "Could not retrieve value from ThemedResourceCache#mUnthemedEntries"

    invoke-static {v2, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_2
    if-eqz v1, :cond_4

    invoke-virtual {v1}, Landroid/util/LongSparseArray;->clear()V

    :cond_4
    return-void
.end method

.method public static k(Landroid/app/Activity;)Landroid/content/Intent;
    .locals 3

    invoke-virtual {p0}, Landroid/app/Activity;->getParentActivityIntent()Landroid/content/Intent;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    .line 1
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/app/Activity;->getComponentName()Landroid/content/ComponentName;

    move-result-object v0

    invoke-static {p0, v0}, La/b/k/h$i;->m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    move-result-object v0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_1

    const/4 v1, 0x0

    if-nez v0, :cond_1

    return-object v1

    .line 2
    :cond_1
    new-instance v2, Landroid/content/ComponentName;

    invoke-direct {v2, p0, v0}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    :try_start_1
    invoke-static {p0, v2}, La/b/k/h$i;->m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_2

    invoke-static {v2}, Landroid/content/Intent;->makeMainActivity(Landroid/content/ComponentName;)Landroid/content/Intent;

    move-result-object p0

    goto :goto_0

    :cond_2
    new-instance p0, Landroid/content/Intent;

    invoke-direct {p0}, Landroid/content/Intent;-><init>()V

    invoke-virtual {p0, v2}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    move-result-object p0
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0

    :goto_0
    return-object p0

    :catch_0
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "getParentActivityIntent: bad parentActivityName \'"

    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\' in manifest"

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string v0, "NavUtils"

    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-object v1

    :catch_1
    move-exception p0

    .line 3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw v0
.end method

.method public static l(Landroid/content/Context;Landroid/content/ComponentName;)Landroid/content/Intent;
    .locals 2

    invoke-static {p0, p1}, La/b/k/h$i;->m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    new-instance v1, Landroid/content/ComponentName;

    invoke-virtual {p1}, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1, v0}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {p0, v1}, La/b/k/h$i;->m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_1

    invoke-static {v1}, Landroid/content/Intent;->makeMainActivity(Landroid/content/ComponentName;)Landroid/content/Intent;

    move-result-object p0

    goto :goto_0

    :cond_1
    new-instance p0, Landroid/content/Intent;

    invoke-direct {p0}, Landroid/content/Intent;-><init>()V

    invoke-virtual {p0, v1}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    move-result-object p0

    :goto_0
    return-object p0
.end method

.method public static m(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;
    .locals 3

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1d

    if-lt v1, v2, :cond_0

    const v1, 0x100c0280

    goto :goto_0

    :cond_0
    const v1, 0xc0280

    :goto_0
    invoke-virtual {v0, p1, v1}, Landroid/content/pm/PackageManager;->getActivityInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;

    move-result-object p1

    iget-object v0, p1, Landroid/content/pm/ActivityInfo;->parentActivityName:Ljava/lang/String;

    if-eqz v0, :cond_1

    return-object v0

    :cond_1
    iget-object p1, p1, Landroid/content/pm/ActivityInfo;->metaData:Landroid/os/Bundle;

    const/4 v0, 0x0

    if-nez p1, :cond_2

    return-object v0

    :cond_2
    const-string v1, "android.support.PARENT_ACTIVITY"

    invoke-virtual {p1, v1}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-nez p1, :cond_3

    return-object v0

    :cond_3
    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    move-result v0

    const/16 v1, 0x2e

    if-ne v0, v1, :cond_4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :cond_4
    return-object p1
.end method

.method public static n(Landroid/content/Context;)Ljava/io/File;
    .locals 5

    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object p0

    const/4 v0, 0x0

    if-nez p0, :cond_0

    return-object v0

    :cond_0
    const-string v1, ".font"

    invoke-static {v1}, Lb/a/a/a/a;->b(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, "-"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Landroid/os/Process;->myTid()I

    move-result v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    :goto_0
    const/16 v3, 0x64

    if-ge v2, v3, :cond_2

    new-instance v3, Ljava/io/File;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, p0, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    :try_start_0
    invoke-virtual {v3}, Ljava/io/File;->createNewFile()Z

    move-result v4
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v4, :cond_1

    return-object v3

    :catch_0
    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    return-object v0
.end method

.method public static o(Landroid/widget/TextView;)La/f/h/a$a;
    .locals 7

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    new-instance v0, La/f/h/a$a;

    invoke-virtual {p0}, Landroid/widget/TextView;->getTextMetricsParams()Landroid/text/PrecomputedText$Params;

    move-result-object p0

    invoke-direct {v0, p0}, La/f/h/a$a;-><init>(Landroid/text/PrecomputedText$Params;)V

    return-object v0

    :cond_0
    new-instance v0, Landroid/text/TextPaint;

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v2

    invoke-direct {v0, v2}, Landroid/text/TextPaint;-><init>(Landroid/graphics/Paint;)V

    .line 1
    sget-object v2, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_LTR:Landroid/text/TextDirectionHeuristic;

    .line 2
    invoke-virtual {p0}, Landroid/widget/TextView;->getBreakStrategy()I

    move-result v2

    invoke-virtual {p0}, Landroid/widget/TextView;->getHyphenationFrequency()I

    move-result v3

    .line 3
    invoke-virtual {p0}, Landroid/widget/TextView;->getTransformationMethod()Landroid/text/method/TransformationMethod;

    move-result-object v4

    instance-of v4, v4, Landroid/text/method/PasswordTransformationMethod;

    if-eqz v4, :cond_2

    :cond_1
    :pswitch_0
    sget-object p0, Landroid/text/TextDirectionHeuristics;->LTR:Landroid/text/TextDirectionHeuristic;

    goto :goto_1

    :cond_2
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    const/4 v5, 0x0

    const/4 v6, 0x1

    if-lt v4, v1, :cond_3

    invoke-virtual {p0}, Landroid/widget/TextView;->getInputType()I

    move-result v1

    and-int/lit8 v1, v1, 0xf

    const/4 v4, 0x3

    if-ne v1, v4, :cond_3

    invoke-virtual {p0}, Landroid/widget/TextView;->getTextLocale()Ljava/util/Locale;

    move-result-object p0

    invoke-static {p0}, Landroid/icu/text/DecimalFormatSymbols;->getInstance(Ljava/util/Locale;)Landroid/icu/text/DecimalFormatSymbols;

    move-result-object p0

    invoke-virtual {p0}, Landroid/icu/text/DecimalFormatSymbols;->getDigitStrings()[Ljava/lang/String;

    move-result-object p0

    aget-object p0, p0, v5

    invoke-virtual {p0, v5}, Ljava/lang/String;->codePointAt(I)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Character;->getDirectionality(I)B

    move-result p0

    if-eq p0, v6, :cond_5

    const/4 v1, 0x2

    if-ne p0, v1, :cond_1

    goto :goto_0

    :cond_3
    invoke-virtual {p0}, Landroid/widget/TextView;->getLayoutDirection()I

    move-result v1

    if-ne v1, v6, :cond_4

    move v5, v6

    :cond_4
    invoke-virtual {p0}, Landroid/widget/TextView;->getTextDirection()I

    move-result p0

    packed-switch p0, :pswitch_data_0

    if-eqz v5, :cond_6

    :pswitch_1
    sget-object p0, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_1

    :pswitch_2
    sget-object p0, Landroid/text/TextDirectionHeuristics;->LOCALE:Landroid/text/TextDirectionHeuristic;

    goto :goto_1

    :cond_5
    :goto_0
    :pswitch_3
    sget-object p0, Landroid/text/TextDirectionHeuristics;->RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_1

    :pswitch_4
    sget-object p0, Landroid/text/TextDirectionHeuristics;->ANYRTL_LTR:Landroid/text/TextDirectionHeuristic;

    goto :goto_1

    :cond_6
    :pswitch_5
    sget-object p0, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_LTR:Landroid/text/TextDirectionHeuristic;

    .line 4
    :goto_1
    new-instance v1, La/f/h/a$a;

    invoke-direct {v1, v0, p0, v2, v3}, La/f/h/a$a;-><init>(Landroid/text/TextPaint;Landroid/text/TextDirectionHeuristic;II)V

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_4
        :pswitch_0
        :pswitch_3
        :pswitch_2
        :pswitch_5
        :pswitch_1
    .end packed-switch
.end method

.method public static p(Landroid/content/Context;Landroid/os/CancellationSignal;Landroid/net/Uri;)Ljava/nio/ByteBuffer;
    .locals 7

    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object p0

    const/4 v0, 0x0

    :try_start_0
    const-string v1, "r"

    invoke-virtual {p0, p2, v1, p1}, Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;

    move-result-object p0

    if-nez p0, :cond_1

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return-object v0

    :cond_1
    :try_start_1
    new-instance p1, Ljava/io/FileInputStream;

    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->getFileDescriptor()Ljava/io/FileDescriptor;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/io/FileInputStream;-><init>(Ljava/io/FileDescriptor;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    :try_start_2
    invoke-virtual {p1}, Ljava/io/FileInputStream;->getChannel()Ljava/nio/channels/FileChannel;

    move-result-object v1

    invoke-virtual {v1}, Ljava/nio/channels/FileChannel;->size()J

    move-result-wide v5

    sget-object v2, Ljava/nio/channels/FileChannel$MapMode;->READ_ONLY:Ljava/nio/channels/FileChannel$MapMode;

    const-wide/16 v3, 0x0

    invoke-virtual/range {v1 .. v6}, Ljava/nio/channels/FileChannel;->map(Ljava/nio/channels/FileChannel$MapMode;JJ)Ljava/nio/MappedByteBuffer;

    move-result-object p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :try_start_3
    invoke-virtual {p1}, Ljava/io/FileInputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :try_start_4
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    return-object p2

    :catchall_0
    move-exception p2

    :try_start_5
    invoke-virtual {p1}, Ljava/io/FileInputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p1

    :try_start_6
    invoke-virtual {p2, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_0
    throw p2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    :catchall_2
    move-exception p1

    :try_start_7
    invoke-virtual {p0}, Landroid/os/ParcelFileDescriptor;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    goto :goto_1

    :catchall_3
    move-exception p0

    :try_start_8
    invoke-virtual {p1, p0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1
    throw p1
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_0

    :catch_0
    return-object v0
.end method

.method public static q(Landroid/view/inputmethod/InputConnection;Landroid/view/inputmethod/EditorInfo;Landroid/view/View;)Landroid/view/inputmethod/InputConnection;
    .locals 1

    if-eqz p0, :cond_1

    iget-object v0, p1, Landroid/view/inputmethod/EditorInfo;->hintText:Ljava/lang/CharSequence;

    if-nez v0, :cond_1

    invoke-virtual {p2}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p2

    :goto_0
    instance-of v0, p2, Landroid/view/View;

    if-eqz v0, :cond_1

    instance-of v0, p2, La/b/p/e1;

    if-eqz v0, :cond_0

    check-cast p2, La/b/p/e1;

    invoke-interface {p2}, La/b/p/e1;->a()Ljava/lang/CharSequence;

    move-result-object p2

    iput-object p2, p1, Landroid/view/inputmethod/EditorInfo;->hintText:Ljava/lang/CharSequence;

    goto :goto_1

    :cond_0
    invoke-interface {p2}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    move-result-object p2

    goto :goto_0

    :cond_1
    :goto_1
    return-object p0
.end method

.method public static r(Landroid/view/ViewParent;Landroid/view/View;FFZ)Z
    .locals 0

    :try_start_0
    invoke-interface {p0, p1, p2, p3, p4}, Landroid/view/ViewParent;->onNestedFling(Landroid/view/View;FFZ)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p1

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string p3, "ViewParent "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " does not implement interface method onNestedFling"

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string p2, "ViewParentCompat"

    invoke-static {p2, p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    const/4 p0, 0x0

    return p0
.end method

.method public static s(Landroid/view/ViewParent;Landroid/view/View;FF)Z
    .locals 0

    :try_start_0
    invoke-interface {p0, p1, p2, p3}, Landroid/view/ViewParent;->onNestedPreFling(Landroid/view/View;FF)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p1

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string p3, "ViewParent "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " does not implement interface method onNestedPreFling"

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string p2, "ViewParentCompat"

    invoke-static {p2, p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    const/4 p0, 0x0

    return p0
.end method

.method public static t(Landroid/view/ViewParent;Landroid/view/View;II[II)V
    .locals 7

    instance-of v0, p0, La/f/j/f;

    if-eqz v0, :cond_0

    move-object v1, p0

    check-cast v1, La/f/j/f;

    move-object v2, p1

    move v3, p2

    move v4, p3

    move-object v5, p4

    move v6, p5

    invoke-interface/range {v1 .. v6}, La/f/j/f;->n(Landroid/view/View;II[II)V

    goto :goto_0

    :cond_0
    if-nez p5, :cond_1

    :try_start_0
    invoke-interface {p0, p1, p2, p3, p4}, Landroid/view/ViewParent;->onNestedPreScroll(Landroid/view/View;II[I)V
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string p3, "ViewParent "

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " does not implement interface method onNestedPreScroll"

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string p2, "ViewParentCompat"

    invoke-static {p2, p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_1
    :goto_0
    return-void
.end method

.method public static u(Landroid/view/ViewParent;Landroid/view/View;IIIII[I)V
    .locals 10

    move-object v1, p0

    instance-of v0, v1, La/f/j/g;

    if-eqz v0, :cond_0

    check-cast v1, La/f/j/g;

    move-object v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    move/from16 v7, p6

    move-object/from16 v8, p7

    invoke-interface/range {v1 .. v8}, La/f/j/g;->k(Landroid/view/View;IIIII[I)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    aget v2, p7, v0

    add-int/2addr v2, p4

    aput v2, p7, v0

    const/4 v0, 0x1

    aget v2, p7, v0

    add-int/2addr v2, p5

    aput v2, p7, v0

    instance-of v0, v1, La/f/j/f;

    if-eqz v0, :cond_1

    move-object v3, v1

    check-cast v3, La/f/j/f;

    move-object v4, p1

    move v5, p2

    move v6, p3

    move v7, p4

    move v8, p5

    move/from16 v9, p6

    invoke-interface/range {v3 .. v9}, La/f/j/f;->l(Landroid/view/View;IIIII)V

    goto :goto_0

    :cond_1
    if-nez p6, :cond_2

    :try_start_0
    invoke-interface/range {p0 .. p5}, Landroid/view/ViewParent;->onNestedScroll(Landroid/view/View;IIII)V
    :try_end_0
    .catch Ljava/lang/AbstractMethodError; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    move-object v2, v0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "ViewParent "

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " does not implement interface method onNestedScroll"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "ViewParentCompat"

    invoke-static {v1, v0, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_2
    :goto_0
    return-void
.end method

.method public static v(Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources;)La/f/d/b/a;
    .locals 18

    move-object/from16 v0, p1

    :goto_0
    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v1

    const/4 v2, 0x1

    const/4 v3, 0x2

    if-eq v1, v3, :cond_0

    if-eq v1, v2, :cond_0

    goto :goto_0

    :cond_0
    if-ne v1, v3, :cond_f

    const/4 v1, 0x0

    const-string v4, "font-family"

    move-object/from16 v5, p0

    .line 1
    invoke-interface {v5, v3, v1, v4}, Lorg/xmlpull/v1/XmlPullParser;->require(ILjava/lang/String;Ljava/lang/String;)V

    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v6, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_e

    .line 2
    invoke-static/range {p0 .. p0}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    move-result-object v4

    sget-object v6, La/f/b;->FontFamily:[I

    invoke-virtual {v0, v4, v6}, Landroid/content/res/Resources;->obtainAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v4

    sget v6, La/f/b;->FontFamily_fontProviderAuthority:I

    invoke-virtual {v4, v6}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v6

    sget v7, La/f/b;->FontFamily_fontProviderPackage:I

    invoke-virtual {v4, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v7

    sget v8, La/f/b;->FontFamily_fontProviderQuery:I

    invoke-virtual {v4, v8}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v8

    sget v9, La/f/b;->FontFamily_fontProviderCerts:I

    const/4 v10, 0x0

    invoke-virtual {v4, v9, v10}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v9

    sget v11, La/f/b;->FontFamily_fontProviderFetchStrategy:I

    invoke-virtual {v4, v11, v2}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v11

    sget v12, La/f/b;->FontFamily_fontProviderFetchTimeout:I

    const/16 v13, 0x1f4

    invoke-virtual {v4, v12, v13}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v12

    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    const/4 v4, 0x3

    if-eqz v6, :cond_2

    if-eqz v7, :cond_2

    if-eqz v8, :cond_2

    :goto_1
    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v1

    if-eq v1, v4, :cond_1

    invoke-static/range {p0 .. p0}, La/b/k/h$i;->C(Lorg/xmlpull/v1/XmlPullParser;)V

    goto :goto_1

    :cond_1
    invoke-static {v0, v9}, La/b/k/h$i;->w(Landroid/content/res/Resources;I)Ljava/util/List;

    move-result-object v0

    new-instance v1, La/f/d/b/d;

    new-instance v2, La/f/g/a;

    invoke-direct {v2, v6, v7, v8, v0}, La/f/g/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    invoke-direct {v1, v2, v11, v12}, La/f/d/b/d;-><init>(La/f/g/a;II)V

    goto/16 :goto_a

    :cond_2
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    :goto_2
    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v7

    if-eq v7, v4, :cond_c

    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    move-result v7

    if-eq v7, v3, :cond_3

    goto :goto_2

    :cond_3
    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    move-result-object v7

    const-string v8, "font"

    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_b

    .line 3
    invoke-static/range {p0 .. p0}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    move-result-object v7

    sget-object v8, La/f/b;->FontFamilyFont:[I

    invoke-virtual {v0, v7, v8}, Landroid/content/res/Resources;->obtainAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v7

    sget v8, La/f/b;->FontFamilyFont_fontWeight:I

    invoke-virtual {v7, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v8

    if-eqz v8, :cond_4

    sget v8, La/f/b;->FontFamilyFont_fontWeight:I

    goto :goto_3

    :cond_4
    sget v8, La/f/b;->FontFamilyFont_android_fontWeight:I

    :goto_3
    const/16 v9, 0x190

    invoke-virtual {v7, v8, v9}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v13

    sget v8, La/f/b;->FontFamilyFont_fontStyle:I

    invoke-virtual {v7, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v8

    if-eqz v8, :cond_5

    sget v8, La/f/b;->FontFamilyFont_fontStyle:I

    goto :goto_4

    :cond_5
    sget v8, La/f/b;->FontFamilyFont_android_fontStyle:I

    :goto_4
    invoke-virtual {v7, v8, v10}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v8

    if-ne v2, v8, :cond_6

    move v14, v2

    goto :goto_5

    :cond_6
    move v14, v10

    :goto_5
    sget v8, La/f/b;->FontFamilyFont_ttcIndex:I

    invoke-virtual {v7, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v8

    if-eqz v8, :cond_7

    sget v8, La/f/b;->FontFamilyFont_ttcIndex:I

    goto :goto_6

    :cond_7
    sget v8, La/f/b;->FontFamilyFont_android_ttcIndex:I

    :goto_6
    sget v9, La/f/b;->FontFamilyFont_fontVariationSettings:I

    invoke-virtual {v7, v9}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v9

    if-eqz v9, :cond_8

    sget v9, La/f/b;->FontFamilyFont_fontVariationSettings:I

    goto :goto_7

    :cond_8
    sget v9, La/f/b;->FontFamilyFont_android_fontVariationSettings:I

    :goto_7
    invoke-virtual {v7, v9}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v7, v8, v10}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v16

    sget v8, La/f/b;->FontFamilyFont_font:I

    invoke-virtual {v7, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v8

    if-eqz v8, :cond_9

    sget v8, La/f/b;->FontFamilyFont_font:I

    goto :goto_8

    :cond_9
    sget v8, La/f/b;->FontFamilyFont_android_font:I

    :goto_8
    invoke-virtual {v7, v8, v10}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v17

    invoke-virtual {v7, v8}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v12

    invoke-virtual {v7}, Landroid/content/res/TypedArray;->recycle()V

    :goto_9
    invoke-interface/range {p0 .. p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v7

    if-eq v7, v4, :cond_a

    invoke-static/range {p0 .. p0}, La/b/k/h$i;->C(Lorg/xmlpull/v1/XmlPullParser;)V

    goto :goto_9

    :cond_a
    new-instance v7, La/f/d/b/c;

    move-object v11, v7

    invoke-direct/range {v11 .. v17}, La/f/d/b/c;-><init>(Ljava/lang/String;IZLjava/lang/String;II)V

    .line 4
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_2

    :cond_b
    invoke-static/range {p0 .. p0}, La/b/k/h$i;->C(Lorg/xmlpull/v1/XmlPullParser;)V

    goto/16 :goto_2

    :cond_c
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_d

    goto :goto_a

    :cond_d
    new-instance v1, La/f/d/b/b;

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v0

    new-array v0, v0, [La/f/d/b/c;

    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [La/f/d/b/c;

    invoke-direct {v1, v0}, La/f/d/b/b;-><init>([La/f/d/b/c;)V

    goto :goto_a

    .line 5
    :cond_e
    invoke-static/range {p0 .. p0}, La/b/k/h$i;->C(Lorg/xmlpull/v1/XmlPullParser;)V

    :goto_a
    return-object v1

    .line 6
    :cond_f
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    const-string v1, "No start tag found"

    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static w(Landroid/content/res/Resources;I)Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/res/Resources;",
            "I)",
            "Ljava/util/List<",
            "Ljava/util/List<",
            "[B>;>;"
        }
    .end annotation

    if-nez p1, :cond_0

    invoke-static {}, Ljava/util/Collections;->emptyList()Ljava/util/List;

    move-result-object p0

    return-object p0

    :cond_0
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->obtainTypedArray(I)Landroid/content/res/TypedArray;

    move-result-object v0

    :try_start_0
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->length()I

    move-result v1

    if-nez v1, :cond_1

    invoke-static {}, Ljava/util/Collections;->emptyList()Ljava/util/List;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    return-object p0

    :cond_1
    :try_start_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    const/4 v2, 0x0

    .line 1
    invoke-virtual {v0, v2}, Landroid/content/res/TypedArray;->getType(I)I

    move-result v3

    const/4 v4, 0x1

    if-ne v3, v4, :cond_3

    move p1, v2

    .line 2
    :goto_0
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->length()I

    move-result v3

    if-ge p1, v3, :cond_4

    invoke-virtual {v0, p1, v2}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {p0, v3}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, La/b/k/h$i;->D([Ljava/lang/String;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2
    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_3
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, La/b/k/h$i;->D([Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_4
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    return-object v1

    :catchall_0
    move-exception p0

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    throw p0
.end method

.method public static x(Landroid/widget/TextView;I)V
    .locals 3

    invoke-static {p1}, La/b/k/h$i;->c(I)I

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    invoke-virtual {p0, p1}, Landroid/widget/TextView;->setFirstBaselineToTopHeight(I)V

    return-void

    :cond_0
    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    invoke-virtual {v0}, Landroid/text/TextPaint;->getFontMetricsInt()Landroid/graphics/Paint$FontMetricsInt;

    move-result-object v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getIncludeFontPadding()Z

    move-result v1

    if-eqz v1, :cond_1

    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->top:I

    goto :goto_0

    :cond_1
    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    :goto_0
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    move-result v1

    if-le p1, v1, :cond_2

    add-int/2addr p1, v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingLeft()I

    move-result v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingRight()I

    move-result v1

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingBottom()I

    move-result v2

    invoke-virtual {p0, v0, p1, v1, v2}, Landroid/widget/TextView;->setPadding(IIII)V

    :cond_2
    return-void
.end method

.method public static y(Landroid/widget/TextView;I)V
    .locals 3

    invoke-static {p1}, La/b/k/h$i;->c(I)I

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    invoke-virtual {v0}, Landroid/text/TextPaint;->getFontMetricsInt()Landroid/graphics/Paint$FontMetricsInt;

    move-result-object v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getIncludeFontPadding()Z

    move-result v1

    if-eqz v1, :cond_0

    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    goto :goto_0

    :cond_0
    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    :goto_0
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    move-result v1

    if-le p1, v1, :cond_1

    sub-int/2addr p1, v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingLeft()I

    move-result v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingTop()I

    move-result v1

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaddingRight()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2, p1}, Landroid/widget/TextView;->setPadding(IIII)V

    :cond_1
    return-void
.end method

.method public static z(Landroid/widget/TextView;I)V
    .locals 2

    invoke-static {p1}, La/b/k/h$i;->c(I)I

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/text/TextPaint;->getFontMetricsInt(Landroid/graphics/Paint$FontMetricsInt;)I

    move-result v0

    if-eq p1, v0, :cond_0

    sub-int/2addr p1, v0

    int-to-float p1, p1

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-virtual {p0, p1, v0}, Landroid/widget/TextView;->setLineSpacing(FF)V

    :cond_0
    return-void
.end method
