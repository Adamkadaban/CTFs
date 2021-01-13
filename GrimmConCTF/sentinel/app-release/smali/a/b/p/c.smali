.class public La/b/p/c;
.super La/b/o/i/b;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/p/c$b;,
        La/b/p/c$c;,
        La/b/p/c$f;,
        La/b/p/c$a;,
        La/b/p/c$e;,
        La/b/p/c$d;
    }
.end annotation


# instance fields
.field public j:La/b/p/c$d;

.field public k:Landroid/graphics/drawable/Drawable;

.field public l:Z

.field public m:Z

.field public n:Z

.field public o:I

.field public p:I

.field public q:I

.field public r:Z

.field public s:I

.field public final t:Landroid/util/SparseBooleanArray;

.field public u:La/b/p/c$e;

.field public v:La/b/p/c$a;

.field public w:La/b/p/c$c;

.field public x:La/b/p/c$b;

.field public final y:La/b/p/c$f;

.field public z:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    sget v0, La/b/g;->abc_action_menu_layout:I

    sget v1, La/b/g;->abc_action_menu_item_layout:I

    invoke-direct {p0, p1, v0, v1}, La/b/o/i/b;-><init>(Landroid/content/Context;II)V

    new-instance p1, Landroid/util/SparseBooleanArray;

    invoke-direct {p1}, Landroid/util/SparseBooleanArray;-><init>()V

    iput-object p1, p0, La/b/p/c;->t:Landroid/util/SparseBooleanArray;

    new-instance p1, La/b/p/c$f;

    invoke-direct {p1, p0}, La/b/p/c$f;-><init>(La/b/p/c;)V

    iput-object p1, p0, La/b/p/c;->y:La/b/p/c$f;

    return-void
.end method


# virtual methods
.method public a(La/b/o/i/i;Landroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 2

    invoke-virtual {p1}, La/b/o/i/i;->getActionView()Landroid/view/View;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, La/b/o/i/i;->f()Z

    move-result v1

    if-eqz v1, :cond_1

    :cond_0
    invoke-super {p0, p1, p2, p3}, La/b/o/i/b;->a(La/b/o/i/i;Landroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v0

    .line 1
    :cond_1
    iget-boolean p1, p1, La/b/o/i/i;->C:Z

    if-eqz p1, :cond_2

    const/16 p1, 0x8

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    .line 2
    :goto_0
    invoke-virtual {v0, p1}, Landroid/view/View;->setVisibility(I)V

    check-cast p3, Landroidx/appcompat/widget/ActionMenuView;

    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p1

    invoke-virtual {p3, p1}, Landroidx/appcompat/widget/ActionMenuView;->checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z

    move-result p2

    if-nez p2, :cond_3

    invoke-virtual {p3, p1}, Landroidx/appcompat/widget/ActionMenuView;->q(Landroid/view/ViewGroup$LayoutParams;)Landroidx/appcompat/widget/ActionMenuView$c;

    move-result-object p1

    invoke-virtual {v0, p1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_3
    return-object v0
.end method

.method public b(La/b/o/i/g;Z)V
    .locals 1

    invoke-virtual {p0}, La/b/p/c;->e()Z

    .line 1
    iget-object v0, p0, La/b/o/i/b;->f:La/b/o/i/m$a;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2}, La/b/o/i/m$a;->b(La/b/o/i/g;Z)V

    :cond_0
    return-void
.end method

.method public e()Z
    .locals 2

    invoke-virtual {p0}, La/b/p/c;->i()Z

    move-result v0

    invoke-virtual {p0}, La/b/p/c;->l()Z

    move-result v1

    or-int/2addr v0, v1

    return v0
.end method

.method public f(La/b/o/i/r;)Z
    .locals 8

    invoke-virtual {p1}, La/b/o/i/g;->hasVisibleItems()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return v1

    :cond_0
    move-object v0, p1

    .line 1
    :goto_0
    iget-object v2, v0, La/b/o/i/r;->A:La/b/o/i/g;

    .line 2
    iget-object v3, p0, La/b/o/i/b;->d:La/b/o/i/g;

    if-eq v2, v3, :cond_1

    move-object v0, v2

    check-cast v0, La/b/o/i/r;

    goto :goto_0

    .line 3
    :cond_1
    iget-object v0, v0, La/b/o/i/r;->B:La/b/o/i/i;

    .line 4
    iget-object v2, p0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast v2, Landroid/view/ViewGroup;

    const/4 v3, 0x0

    if-nez v2, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v4

    move v5, v1

    :goto_1
    if-ge v5, v4, :cond_4

    invoke-virtual {v2, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v6

    instance-of v7, v6, La/b/o/i/n$a;

    if-eqz v7, :cond_3

    move-object v7, v6

    check-cast v7, La/b/o/i/n$a;

    invoke-interface {v7}, La/b/o/i/n$a;->getItemData()La/b/o/i/i;

    move-result-object v7

    if-ne v7, v0, :cond_3

    move-object v3, v6

    goto :goto_2

    :cond_3
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_4
    :goto_2
    if-nez v3, :cond_5

    return v1

    .line 5
    :cond_5
    iget-object v0, p1, La/b/o/i/r;->B:La/b/o/i/i;

    .line 6
    iget v0, v0, La/b/o/i/i;->a:I

    .line 7
    invoke-virtual {p1}, La/b/o/i/g;->size()I

    move-result v0

    move v2, v1

    :goto_3
    const/4 v4, 0x1

    if-ge v2, v0, :cond_7

    invoke-virtual {p1, v2}, La/b/o/i/g;->getItem(I)Landroid/view/MenuItem;

    move-result-object v5

    invoke-interface {v5}, Landroid/view/MenuItem;->isVisible()Z

    move-result v6

    if-eqz v6, :cond_6

    invoke-interface {v5}, Landroid/view/MenuItem;->getIcon()Landroid/graphics/drawable/Drawable;

    move-result-object v5

    if-eqz v5, :cond_6

    move v1, v4

    goto :goto_4

    :cond_6
    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    :cond_7
    :goto_4
    new-instance v0, La/b/p/c$a;

    iget-object v2, p0, La/b/o/i/b;->c:Landroid/content/Context;

    invoke-direct {v0, p0, v2, p1, v3}, La/b/p/c$a;-><init>(La/b/p/c;Landroid/content/Context;La/b/o/i/r;Landroid/view/View;)V

    iput-object v0, p0, La/b/p/c;->v:La/b/p/c$a;

    .line 8
    iput-boolean v1, v0, La/b/o/i/l;->h:Z

    iget-object v0, v0, La/b/o/i/l;->j:La/b/o/i/k;

    if-eqz v0, :cond_8

    invoke-virtual {v0, v1}, La/b/o/i/k;->p(Z)V

    .line 9
    :cond_8
    iget-object v0, p0, La/b/p/c;->v:La/b/p/c$a;

    .line 10
    invoke-virtual {v0}, La/b/o/i/l;->f()Z

    move-result v0

    if-eqz v0, :cond_9

    .line 11
    invoke-super {p0, p1}, La/b/o/i/b;->f(La/b/o/i/r;)Z

    return v4

    .line 12
    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "MenuPopupHelper cannot be used without an anchor"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public g()Z
    .locals 17

    move-object/from16 v0, p0

    iget-object v1, v0, La/b/o/i/b;->d:La/b/o/i/g;

    const/4 v2, 0x0

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    invoke-virtual {v1}, La/b/o/i/g;->l()Ljava/util/ArrayList;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v4

    goto :goto_0

    :cond_0
    move-object v1, v2

    move v4, v3

    :goto_0
    iget v5, v0, La/b/p/c;->q:I

    iget v6, v0, La/b/p/c;->p:I

    invoke-static {v3, v3}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v7

    iget-object v8, v0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast v8, Landroid/view/ViewGroup;

    move v9, v3

    move v10, v9

    move v11, v10

    move v12, v11

    :goto_1
    const/4 v13, 0x2

    const/4 v14, 0x1

    if-ge v9, v4, :cond_6

    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v15

    check-cast v15, La/b/o/i/i;

    .line 1
    iget v3, v15, La/b/o/i/i;->y:I

    and-int/2addr v3, v13

    if-ne v3, v13, :cond_1

    move v3, v14

    goto :goto_2

    :cond_1
    const/4 v3, 0x0

    :goto_2
    if-eqz v3, :cond_2

    add-int/lit8 v12, v12, 0x1

    goto :goto_4

    .line 2
    :cond_2
    iget v3, v15, La/b/o/i/i;->y:I

    and-int/2addr v3, v14

    if-ne v3, v14, :cond_3

    move v3, v14

    goto :goto_3

    :cond_3
    const/4 v3, 0x0

    :goto_3
    if-eqz v3, :cond_4

    add-int/lit8 v11, v11, 0x1

    goto :goto_4

    :cond_4
    move v10, v14

    .line 3
    :goto_4
    iget-boolean v3, v0, La/b/p/c;->r:Z

    if-eqz v3, :cond_5

    .line 4
    iget-boolean v3, v15, La/b/o/i/i;->C:Z

    if-eqz v3, :cond_5

    const/4 v5, 0x0

    :cond_5
    add-int/lit8 v9, v9, 0x1

    const/4 v3, 0x0

    goto :goto_1

    .line 5
    :cond_6
    iget-boolean v3, v0, La/b/p/c;->m:Z

    if-eqz v3, :cond_8

    if-nez v10, :cond_7

    add-int/2addr v11, v12

    if-le v11, v5, :cond_8

    :cond_7
    add-int/lit8 v5, v5, -0x1

    :cond_8
    sub-int/2addr v5, v12

    iget-object v3, v0, La/b/p/c;->t:Landroid/util/SparseBooleanArray;

    invoke-virtual {v3}, Landroid/util/SparseBooleanArray;->clear()V

    const/4 v9, 0x0

    const/4 v10, 0x0

    :goto_5
    if-ge v9, v4, :cond_19

    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, La/b/o/i/i;

    .line 6
    iget v12, v11, La/b/o/i/i;->y:I

    and-int/2addr v12, v13

    if-ne v12, v13, :cond_9

    move v12, v14

    goto :goto_6

    :cond_9
    const/4 v12, 0x0

    :goto_6
    if-eqz v12, :cond_c

    .line 7
    invoke-virtual {v0, v11, v2, v8}, La/b/p/c;->a(La/b/o/i/i;Landroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v12

    invoke-virtual {v12, v7, v7}, Landroid/view/View;->measure(II)V

    invoke-virtual {v12}, Landroid/view/View;->getMeasuredWidth()I

    move-result v12

    sub-int/2addr v6, v12

    if-nez v10, :cond_a

    move v10, v12

    .line 8
    :cond_a
    iget v12, v11, La/b/o/i/i;->b:I

    if-eqz v12, :cond_b

    .line 9
    invoke-virtual {v3, v12, v14}, Landroid/util/SparseBooleanArray;->put(IZ)V

    :cond_b
    invoke-virtual {v11, v14}, La/b/o/i/i;->k(Z)V

    goto/16 :goto_c

    .line 10
    :cond_c
    iget v12, v11, La/b/o/i/i;->y:I

    and-int/2addr v12, v14

    if-ne v12, v14, :cond_d

    move v12, v14

    goto :goto_7

    :cond_d
    const/4 v12, 0x0

    :goto_7
    if-eqz v12, :cond_18

    .line 11
    iget v12, v11, La/b/o/i/i;->b:I

    .line 12
    invoke-virtual {v3, v12}, Landroid/util/SparseBooleanArray;->get(I)Z

    move-result v15

    if-gtz v5, :cond_e

    if-eqz v15, :cond_f

    :cond_e
    if-lez v6, :cond_f

    move/from16 v16, v14

    goto :goto_8

    :cond_f
    const/16 v16, 0x0

    :goto_8
    if-eqz v16, :cond_12

    invoke-virtual {v0, v11, v2, v8}, La/b/p/c;->a(La/b/o/i/i;Landroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v13

    invoke-virtual {v13, v7, v7}, Landroid/view/View;->measure(II)V

    invoke-virtual {v13}, Landroid/view/View;->getMeasuredWidth()I

    move-result v13

    sub-int/2addr v6, v13

    if-nez v10, :cond_10

    move v10, v13

    :cond_10
    add-int v13, v6, v10

    if-lez v13, :cond_11

    move v13, v14

    goto :goto_9

    :cond_11
    const/4 v13, 0x0

    :goto_9
    and-int v16, v16, v13

    :cond_12
    move/from16 v13, v16

    if-eqz v13, :cond_13

    if-eqz v12, :cond_13

    invoke-virtual {v3, v12, v14}, Landroid/util/SparseBooleanArray;->put(IZ)V

    goto :goto_b

    :cond_13
    if-eqz v15, :cond_16

    const/4 v15, 0x0

    invoke-virtual {v3, v12, v15}, Landroid/util/SparseBooleanArray;->put(IZ)V

    const/4 v15, 0x0

    :goto_a
    if-ge v15, v9, :cond_16

    invoke-virtual {v1, v15}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v2, v16

    check-cast v2, La/b/o/i/i;

    .line 13
    iget v14, v2, La/b/o/i/i;->b:I

    if-ne v14, v12, :cond_15

    .line 14
    invoke-virtual {v2}, La/b/o/i/i;->g()Z

    move-result v14

    if-eqz v14, :cond_14

    add-int/lit8 v5, v5, 0x1

    :cond_14
    const/4 v14, 0x0

    invoke-virtual {v2, v14}, La/b/o/i/i;->k(Z)V

    :cond_15
    add-int/lit8 v15, v15, 0x1

    const/4 v2, 0x0

    const/4 v14, 0x1

    goto :goto_a

    :cond_16
    :goto_b
    if-eqz v13, :cond_17

    add-int/lit8 v5, v5, -0x1

    :cond_17
    invoke-virtual {v11, v13}, La/b/o/i/i;->k(Z)V

    :goto_c
    const/4 v2, 0x0

    goto :goto_d

    :cond_18
    const/4 v2, 0x0

    invoke-virtual {v11, v2}, La/b/o/i/i;->k(Z)V

    :goto_d
    add-int/lit8 v9, v9, 0x1

    const/4 v2, 0x0

    const/4 v13, 0x2

    const/4 v14, 0x1

    goto/16 :goto_5

    :cond_19
    move v5, v14

    return v5
.end method

.method public h(Z)V
    .locals 4

    invoke-super {p0, p1}, La/b/o/i/b;->h(Z)V

    iget-object p1, p0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast p1, Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->requestLayout()V

    iget-object p1, p0, La/b/o/i/b;->d:La/b/o/i/g;

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    .line 1
    invoke-virtual {p1}, La/b/o/i/g;->i()V

    iget-object p1, p1, La/b/o/i/g;->i:Ljava/util/ArrayList;

    .line 2
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    move v2, v0

    :goto_0
    if-ge v2, v1, :cond_0

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La/b/o/i/i;

    .line 3
    iget-object v3, v3, La/b/o/i/i;->A:La/f/j/b;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 4
    :cond_0
    iget-object p1, p0, La/b/o/i/b;->d:La/b/o/i/g;

    if-eqz p1, :cond_1

    .line 5
    invoke-virtual {p1}, La/b/o/i/g;->i()V

    iget-object p1, p1, La/b/o/i/g;->j:Ljava/util/ArrayList;

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    .line 6
    :goto_1
    iget-boolean v1, p0, La/b/p/c;->m:Z

    const/4 v2, 0x1

    if-eqz v1, :cond_3

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ne v1, v2, :cond_2

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, La/b/o/i/i;

    .line 7
    iget-boolean p1, p1, La/b/o/i/i;->C:Z

    xor-int/lit8 v0, p1, 0x1

    goto :goto_2

    :cond_2
    if-lez v1, :cond_3

    move v0, v2

    .line 8
    :cond_3
    :goto_2
    iget-object p1, p0, La/b/p/c;->j:La/b/p/c$d;

    if-eqz v0, :cond_6

    if-nez p1, :cond_4

    new-instance p1, La/b/p/c$d;

    iget-object v0, p0, La/b/o/i/b;->b:Landroid/content/Context;

    invoke-direct {p1, p0, v0}, La/b/p/c$d;-><init>(La/b/p/c;Landroid/content/Context;)V

    iput-object p1, p0, La/b/p/c;->j:La/b/p/c$d;

    :cond_4
    iget-object p1, p0, La/b/p/c;->j:La/b/p/c$d;

    invoke-virtual {p1}, Landroid/widget/ImageView;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    check-cast p1, Landroid/view/ViewGroup;

    iget-object v0, p0, La/b/o/i/b;->i:La/b/o/i/n;

    if-eq p1, v0, :cond_7

    if-eqz p1, :cond_5

    iget-object v0, p0, La/b/p/c;->j:La/b/p/c$d;

    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_5
    iget-object p1, p0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast p1, Landroidx/appcompat/widget/ActionMenuView;

    iget-object v0, p0, La/b/p/c;->j:La/b/p/c$d;

    .line 9
    invoke-virtual {p1}, Landroidx/appcompat/widget/ActionMenuView;->p()Landroidx/appcompat/widget/ActionMenuView$c;

    move-result-object v1

    iput-boolean v2, v1, Landroidx/appcompat/widget/ActionMenuView$c;->c:Z

    .line 10
    invoke-virtual {p1, v0, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    goto :goto_3

    :cond_6
    if-eqz p1, :cond_7

    invoke-virtual {p1}, Landroid/widget/ImageView;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    iget-object v0, p0, La/b/o/i/b;->i:La/b/o/i/n;

    if-ne p1, v0, :cond_7

    check-cast v0, Landroid/view/ViewGroup;

    iget-object p1, p0, La/b/p/c;->j:La/b/p/c$d;

    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    :cond_7
    :goto_3
    iget-object p1, p0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast p1, Landroidx/appcompat/widget/ActionMenuView;

    iget-boolean v0, p0, La/b/p/c;->m:Z

    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionMenuView;->setOverflowReserved(Z)V

    return-void
.end method

.method public i()Z
    .locals 3

    iget-object v0, p0, La/b/p/c;->w:La/b/p/c$c;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-object v2, p0, La/b/o/i/b;->i:La/b/o/i/n;

    if-eqz v2, :cond_0

    check-cast v2, Landroid/view/View;

    invoke-virtual {v2, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    const/4 v0, 0x0

    iput-object v0, p0, La/b/p/c;->w:La/b/p/c$c;

    return v1

    :cond_0
    iget-object v0, p0, La/b/p/c;->u:La/b/p/c$e;

    if-eqz v0, :cond_2

    .line 1
    invoke-virtual {v0}, La/b/o/i/l;->b()Z

    move-result v2

    if-eqz v2, :cond_1

    iget-object v0, v0, La/b/o/i/l;->j:La/b/o/i/k;

    invoke-interface {v0}, La/b/o/i/p;->dismiss()V

    :cond_1
    return v1

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public j(Landroid/content/Context;La/b/o/i/g;)V
    .locals 4

    .line 1
    iput-object p1, p0, La/b/o/i/b;->c:Landroid/content/Context;

    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    iput-object p2, p0, La/b/o/i/b;->d:La/b/o/i/g;

    .line 2
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p2

    iget-boolean v0, p0, La/b/p/c;->n:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/p/c;->m:Z

    .line 3
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    iget v0, v0, Landroid/util/DisplayMetrics;->widthPixels:I

    const/4 v1, 0x2

    div-int/2addr v0, v1

    .line 4
    iput v0, p0, La/b/p/c;->o:I

    .line 5
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object p1

    iget v0, p1, Landroid/content/res/Configuration;->screenWidthDp:I

    iget v2, p1, Landroid/content/res/Configuration;->screenHeightDp:I

    iget p1, p1, Landroid/content/res/Configuration;->smallestScreenWidthDp:I

    const/16 v3, 0x258

    if-gt p1, v3, :cond_6

    if-gt v0, v3, :cond_6

    const/16 p1, 0x2d0

    const/16 v3, 0x3c0

    if-le v0, v3, :cond_1

    if-gt v2, p1, :cond_6

    :cond_1
    if-le v0, p1, :cond_2

    if-le v2, v3, :cond_2

    goto :goto_1

    :cond_2
    const/16 p1, 0x1f4

    if-ge v0, p1, :cond_5

    const/16 p1, 0x1e0

    const/16 v3, 0x280

    if-le v0, v3, :cond_3

    if-gt v2, p1, :cond_5

    :cond_3
    if-le v0, p1, :cond_4

    if-le v2, v3, :cond_4

    goto :goto_0

    :cond_4
    const/16 p1, 0x168

    if-lt v0, p1, :cond_7

    const/4 v1, 0x3

    goto :goto_2

    :cond_5
    :goto_0
    const/4 v1, 0x4

    goto :goto_2

    :cond_6
    :goto_1
    const/4 v1, 0x5

    .line 6
    :cond_7
    :goto_2
    iput v1, p0, La/b/p/c;->q:I

    iget p1, p0, La/b/p/c;->o:I

    iget-boolean v0, p0, La/b/p/c;->m:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_a

    iget-object v0, p0, La/b/p/c;->j:La/b/p/c$d;

    if-nez v0, :cond_9

    new-instance v0, La/b/p/c$d;

    iget-object v2, p0, La/b/o/i/b;->b:Landroid/content/Context;

    invoke-direct {v0, p0, v2}, La/b/p/c$d;-><init>(La/b/p/c;Landroid/content/Context;)V

    iput-object v0, p0, La/b/p/c;->j:La/b/p/c$d;

    iget-boolean v2, p0, La/b/p/c;->l:Z

    const/4 v3, 0x0

    if-eqz v2, :cond_8

    iget-object v2, p0, La/b/p/c;->k:Landroid/graphics/drawable/Drawable;

    invoke-virtual {v0, v2}, La/b/p/n;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    iput-object v1, p0, La/b/p/c;->k:Landroid/graphics/drawable/Drawable;

    iput-boolean v3, p0, La/b/p/c;->l:Z

    :cond_8
    invoke-static {v3, v3}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v0

    iget-object v1, p0, La/b/p/c;->j:La/b/p/c$d;

    invoke-virtual {v1, v0, v0}, Landroid/widget/ImageView;->measure(II)V

    :cond_9
    iget-object v0, p0, La/b/p/c;->j:La/b/p/c$d;

    invoke-virtual {v0}, Landroid/widget/ImageView;->getMeasuredWidth()I

    move-result v0

    sub-int/2addr p1, v0

    goto :goto_3

    :cond_a
    iput-object v1, p0, La/b/p/c;->j:La/b/p/c$d;

    :goto_3
    iput p1, p0, La/b/p/c;->p:I

    const/high16 p1, 0x42600000    # 56.0f

    invoke-virtual {p2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object p2

    iget p2, p2, Landroid/util/DisplayMetrics;->density:F

    mul-float/2addr p2, p1

    float-to-int p1, p2

    iput p1, p0, La/b/p/c;->s:I

    return-void
.end method

.method public l()Z
    .locals 2

    iget-object v0, p0, La/b/p/c;->v:La/b/p/c$a;

    if-eqz v0, :cond_1

    .line 1
    invoke-virtual {v0}, La/b/o/i/l;->b()Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v0, v0, La/b/o/i/l;->j:La/b/o/i/k;

    invoke-interface {v0}, La/b/o/i/p;->dismiss()V

    :cond_0
    const/4 v0, 0x1

    return v0

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public m()Z
    .locals 1

    iget-object v0, p0, La/b/p/c;->u:La/b/p/c$e;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, La/b/o/i/l;->b()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public n()Z
    .locals 7

    iget-boolean v0, p0, La/b/p/c;->m:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0}, La/b/p/c;->m()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/o/i/b;->d:La/b/o/i/g;

    if-eqz v0, :cond_0

    iget-object v1, p0, La/b/o/i/b;->i:La/b/o/i/n;

    if-eqz v1, :cond_0

    iget-object v1, p0, La/b/p/c;->w:La/b/p/c$c;

    if-nez v1, :cond_0

    .line 1
    invoke-virtual {v0}, La/b/o/i/g;->i()V

    iget-object v0, v0, La/b/o/i/g;->j:Ljava/util/ArrayList;

    .line 2
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    new-instance v0, La/b/p/c$e;

    iget-object v3, p0, La/b/o/i/b;->c:Landroid/content/Context;

    iget-object v4, p0, La/b/o/i/b;->d:La/b/o/i/g;

    iget-object v5, p0, La/b/p/c;->j:La/b/p/c$d;

    const/4 v6, 0x1

    move-object v1, v0

    move-object v2, p0

    invoke-direct/range {v1 .. v6}, La/b/p/c$e;-><init>(La/b/p/c;Landroid/content/Context;La/b/o/i/g;Landroid/view/View;Z)V

    new-instance v1, La/b/p/c$c;

    invoke-direct {v1, p0, v0}, La/b/p/c$c;-><init>(La/b/p/c;La/b/p/c$e;)V

    iput-object v1, p0, La/b/p/c;->w:La/b/p/c$c;

    iget-object v0, p0, La/b/o/i/b;->i:La/b/o/i/n;

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
