.class public La/b/p/k0;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements La/b/o/i/p;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/p/k0$c;,
        La/b/p/k0$d;,
        La/b/p/k0$e;,
        La/b/p/k0$a;,
        La/b/p/k0$b;
    }
.end annotation


# static fields
.field public static D:Ljava/lang/reflect/Method;

.field public static E:Ljava/lang/reflect/Method;


# instance fields
.field public A:Landroid/graphics/Rect;

.field public B:Z

.field public C:Landroid/widget/PopupWindow;

.field public b:Landroid/content/Context;

.field public c:Landroid/widget/ListAdapter;

.field public d:La/b/p/f0;

.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public i:I

.field public j:Z

.field public k:Z

.field public l:Z

.field public m:I

.field public n:Z

.field public o:Z

.field public p:I

.field public q:I

.field public r:Landroid/database/DataSetObserver;

.field public s:Landroid/view/View;

.field public t:Landroid/widget/AdapterView$OnItemClickListener;

.field public final u:La/b/p/k0$e;

.field public final v:La/b/p/k0$d;

.field public final w:La/b/p/k0$c;

.field public final x:La/b/p/k0$a;

.field public final y:Landroid/os/Handler;

.field public final z:Landroid/graphics/Rect;


# direct methods
.method public static constructor <clinit>()V
    .locals 7

    const-string v0, "ListPopupWindow"

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1c

    if-gt v1, v2, :cond_0

    const/4 v1, 0x0

    const/4 v2, 0x1

    :try_start_0
    const-class v3, Landroid/widget/PopupWindow;

    const-string v4, "setClipToScreenEnabled"

    new-array v5, v2, [Ljava/lang/Class;

    sget-object v6, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    aput-object v6, v5, v1

    invoke-virtual {v3, v4, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v3

    sput-object v3, La/b/p/k0;->D:Ljava/lang/reflect/Method;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    const-string v3, "Could not find method setClipToScreenEnabled() on PopupWindow. Oh well."

    invoke-static {v0, v3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :goto_0
    :try_start_1
    const-class v3, Landroid/widget/PopupWindow;

    const-string v4, "setEpicenterBounds"

    new-array v2, v2, [Ljava/lang/Class;

    const-class v5, Landroid/graphics/Rect;

    aput-object v5, v2, v1

    invoke-virtual {v3, v4, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    sput-object v1, La/b/p/k0;->E:Ljava/lang/reflect/Method;
    :try_end_1
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    :catch_1
    const-string v1, "Could not find method setEpicenterBounds(Rect) on PopupWindow. Oh well."

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    :goto_1
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, -0x2

    iput v0, p0, La/b/p/k0;->e:I

    iput v0, p0, La/b/p/k0;->f:I

    const/16 v0, 0x3ea

    iput v0, p0, La/b/p/k0;->i:I

    const/4 v0, 0x0

    iput v0, p0, La/b/p/k0;->m:I

    iput-boolean v0, p0, La/b/p/k0;->n:Z

    iput-boolean v0, p0, La/b/p/k0;->o:Z

    const v1, 0x7fffffff

    iput v1, p0, La/b/p/k0;->p:I

    iput v0, p0, La/b/p/k0;->q:I

    new-instance v1, La/b/p/k0$e;

    invoke-direct {v1, p0}, La/b/p/k0$e;-><init>(La/b/p/k0;)V

    iput-object v1, p0, La/b/p/k0;->u:La/b/p/k0$e;

    new-instance v1, La/b/p/k0$d;

    invoke-direct {v1, p0}, La/b/p/k0$d;-><init>(La/b/p/k0;)V

    iput-object v1, p0, La/b/p/k0;->v:La/b/p/k0$d;

    new-instance v1, La/b/p/k0$c;

    invoke-direct {v1, p0}, La/b/p/k0$c;-><init>(La/b/p/k0;)V

    iput-object v1, p0, La/b/p/k0;->w:La/b/p/k0$c;

    new-instance v1, La/b/p/k0$a;

    invoke-direct {v1, p0}, La/b/p/k0$a;-><init>(La/b/p/k0;)V

    iput-object v1, p0, La/b/p/k0;->x:La/b/p/k0$a;

    new-instance v1, Landroid/graphics/Rect;

    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    iput-object v1, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    iput-object p1, p0, La/b/p/k0;->b:Landroid/content/Context;

    new-instance v1, Landroid/os/Handler;

    invoke-virtual {p1}, Landroid/content/Context;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object v1, p0, La/b/p/k0;->y:Landroid/os/Handler;

    sget-object v1, La/b/j;->ListPopupWindow:[I

    invoke-virtual {p1, p2, v1, p3, p4}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object v1

    sget v2, La/b/j;->ListPopupWindow_android_dropDownHorizontalOffset:I

    invoke-virtual {v1, v2, v0}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v2

    iput v2, p0, La/b/p/k0;->g:I

    sget v2, La/b/j;->ListPopupWindow_android_dropDownVerticalOffset:I

    invoke-virtual {v1, v2, v0}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v0

    iput v0, p0, La/b/p/k0;->h:I

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    iput-boolean v2, p0, La/b/p/k0;->j:Z

    :cond_0
    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V

    new-instance v0, La/b/p/p;

    invoke-direct {v0, p1, p2, p3, p4}, La/b/p/p;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    iput-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v2}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->isShowing()Z

    move-result v0

    return v0
.end method

.method public c(I)V
    .locals 0

    iput p1, p0, La/b/p/k0;->g:I

    return-void
.end method

.method public d()I
    .locals 1

    iget v0, p0, La/b/p/k0;->g:I

    return v0
.end method

.method public dismiss()V
    .locals 2

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->dismiss()V

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    iput-object v1, p0, La/b/p/k0;->d:La/b/p/f0;

    iget-object v0, p0, La/b/p/k0;->y:Landroid/os/Handler;

    iget-object v1, p0, La/b/p/k0;->u:La/b/p/k0$e;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    return-void
.end method

.method public e()Landroid/widget/ListView;
    .locals 1

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    return-object v0
.end method

.method public i()V
    .locals 14

    .line 1
    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    const/4 v1, 0x1

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/p/k0;->b:Landroid/content/Context;

    iget-boolean v2, p0, La/b/p/k0;->B:Z

    xor-int/2addr v2, v1

    invoke-virtual {p0, v0, v2}, La/b/p/k0;->q(Landroid/content/Context;Z)La/b/p/f0;

    move-result-object v0

    iput-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    iget-object v2, p0, La/b/p/k0;->c:Landroid/widget/ListAdapter;

    invoke-virtual {v0, v2}, Landroid/widget/ListView;->setAdapter(Landroid/widget/ListAdapter;)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    iget-object v2, p0, La/b/p/k0;->t:Landroid/widget/AdapterView$OnItemClickListener;

    invoke-virtual {v0, v2}, Landroid/widget/ListView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v0, v1}, Landroid/widget/ListView;->setFocusable(Z)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v0, v1}, Landroid/widget/ListView;->setFocusableInTouchMode(Z)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    new-instance v2, La/b/p/j0;

    invoke-direct {v2, p0}, La/b/p/j0;-><init>(La/b/p/k0;)V

    invoke-virtual {v0, v2}, Landroid/widget/ListView;->setOnItemSelectedListener(Landroid/widget/AdapterView$OnItemSelectedListener;)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    iget-object v2, p0, La/b/p/k0;->w:La/b/p/k0$c;

    invoke-virtual {v0, v2}, Landroid/widget/ListView;->setOnScrollListener(Landroid/widget/AbsListView$OnScrollListener;)V

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    iget-object v2, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v2, v0}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getContentView()Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup;

    :goto_0
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    iget-object v3, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    invoke-virtual {v0, v3}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    iget-object v0, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    iget v3, v0, Landroid/graphics/Rect;->top:I

    iget v0, v0, Landroid/graphics/Rect;->bottom:I

    add-int/2addr v0, v3

    iget-boolean v4, p0, La/b/p/k0;->j:Z

    if-nez v4, :cond_2

    neg-int v3, v3

    iput v3, p0, La/b/p/k0;->h:I

    goto :goto_1

    :cond_1
    iget-object v0, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    invoke-virtual {v0}, Landroid/graphics/Rect;->setEmpty()V

    move v0, v2

    :cond_2
    :goto_1
    iget-object v3, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v3}, Landroid/widget/PopupWindow;->getInputMethodMode()I

    move-result v3

    const/4 v4, 0x2

    if-ne v3, v4, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v2

    .line 2
    :goto_2
    iget-object v5, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 3
    iget v6, p0, La/b/p/k0;->h:I

    .line 4
    iget-object v7, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v7, v5, v6, v3}, Landroid/widget/PopupWindow;->getMaxAvailableHeight(Landroid/view/View;IZ)I

    move-result v3

    .line 5
    iget-boolean v5, p0, La/b/p/k0;->n:Z

    const/4 v6, -0x2

    const/4 v7, -0x1

    if-nez v5, :cond_8

    iget v5, p0, La/b/p/k0;->e:I

    if-ne v5, v7, :cond_4

    goto :goto_5

    :cond_4
    iget v5, p0, La/b/p/k0;->f:I

    if-eq v5, v6, :cond_6

    const/high16 v8, 0x40000000    # 2.0f

    if-eq v5, v7, :cond_5

    goto :goto_3

    :cond_5
    iget-object v5, p0, La/b/p/k0;->b:Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v5

    iget v5, v5, Landroid/util/DisplayMetrics;->widthPixels:I

    iget-object v9, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    iget v10, v9, Landroid/graphics/Rect;->left:I

    iget v9, v9, Landroid/graphics/Rect;->right:I

    add-int/2addr v10, v9

    sub-int/2addr v5, v10

    goto :goto_3

    :cond_6
    iget-object v5, p0, La/b/p/k0;->b:Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v5

    iget v5, v5, Landroid/util/DisplayMetrics;->widthPixels:I

    iget-object v8, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    iget v9, v8, Landroid/graphics/Rect;->left:I

    iget v8, v8, Landroid/graphics/Rect;->right:I

    add-int/2addr v9, v8

    sub-int/2addr v5, v9

    const/high16 v8, -0x80000000

    :goto_3
    invoke-static {v5, v8}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result v5

    iget-object v8, p0, La/b/p/k0;->d:La/b/p/f0;

    sub-int/2addr v3, v2

    invoke-virtual {v8, v5, v3, v7}, La/b/p/f0;->a(III)I

    move-result v3

    if-lez v3, :cond_7

    iget-object v5, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v5}, Landroid/widget/ListView;->getPaddingTop()I

    move-result v5

    iget-object v8, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v8}, Landroid/widget/ListView;->getPaddingBottom()I

    move-result v8

    add-int/2addr v8, v5

    add-int/2addr v8, v0

    add-int/2addr v8, v2

    goto :goto_4

    :cond_7
    move v8, v2

    :goto_4
    add-int/2addr v3, v8

    goto :goto_6

    :cond_8
    :goto_5
    add-int/2addr v3, v0

    .line 6
    :goto_6
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getInputMethodMode()I

    move-result v0

    if-ne v0, v4, :cond_9

    move v0, v1

    goto :goto_7

    :cond_9
    move v0, v2

    .line 7
    :goto_7
    iget-object v4, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget v5, p0, La/b/p/k0;->i:I

    .line 8
    invoke-virtual {v4, v5}, Landroid/widget/PopupWindow;->setWindowLayoutType(I)V

    .line 9
    iget-object v4, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v4}, Landroid/widget/PopupWindow;->isShowing()Z

    move-result v4

    if-eqz v4, :cond_16

    .line 10
    iget-object v4, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 11
    invoke-static {v4}, La/f/j/k;->l(Landroid/view/View;)Z

    move-result v4

    if-nez v4, :cond_a

    return-void

    :cond_a
    iget v4, p0, La/b/p/k0;->f:I

    if-ne v4, v7, :cond_b

    move v4, v7

    goto :goto_8

    :cond_b
    if-ne v4, v6, :cond_c

    .line 12
    iget-object v4, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 13
    invoke-virtual {v4}, Landroid/view/View;->getWidth()I

    move-result v4

    :cond_c
    :goto_8
    iget v5, p0, La/b/p/k0;->e:I

    if-ne v5, v7, :cond_11

    if-eqz v0, :cond_d

    goto :goto_9

    :cond_d
    move v3, v7

    :goto_9
    if-eqz v0, :cond_f

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget v5, p0, La/b/p/k0;->f:I

    if-ne v5, v7, :cond_e

    move v5, v7

    goto :goto_a

    :cond_e
    move v5, v2

    :goto_a
    invoke-virtual {v0, v5}, Landroid/widget/PopupWindow;->setWidth(I)V

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v2}, Landroid/widget/PopupWindow;->setHeight(I)V

    goto :goto_c

    :cond_f
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget v5, p0, La/b/p/k0;->f:I

    if-ne v5, v7, :cond_10

    move v5, v7

    goto :goto_b

    :cond_10
    move v5, v2

    :goto_b
    invoke-virtual {v0, v5}, Landroid/widget/PopupWindow;->setWidth(I)V

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v7}, Landroid/widget/PopupWindow;->setHeight(I)V

    goto :goto_c

    :cond_11
    if-ne v5, v6, :cond_12

    goto :goto_c

    :cond_12
    move v3, v5

    :goto_c
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget-boolean v5, p0, La/b/p/k0;->o:Z

    if-nez v5, :cond_13

    iget-boolean v5, p0, La/b/p/k0;->n:Z

    if-nez v5, :cond_13

    goto :goto_d

    :cond_13
    move v1, v2

    :goto_d
    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setOutsideTouchable(Z)V

    iget-object v8, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    .line 14
    iget-object v9, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 15
    iget v10, p0, La/b/p/k0;->g:I

    iget v11, p0, La/b/p/k0;->h:I

    if-gez v4, :cond_14

    move v12, v7

    goto :goto_e

    :cond_14
    move v12, v4

    :goto_e
    if-gez v3, :cond_15

    move v13, v7

    goto :goto_f

    :cond_15
    move v13, v3

    :goto_f
    invoke-virtual/range {v8 .. v13}, Landroid/widget/PopupWindow;->update(Landroid/view/View;IIII)V

    goto/16 :goto_15

    :cond_16
    iget v0, p0, La/b/p/k0;->f:I

    if-ne v0, v7, :cond_17

    move v0, v7

    goto :goto_10

    :cond_17
    if-ne v0, v6, :cond_18

    .line 16
    iget-object v0, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 17
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    move-result v0

    :cond_18
    :goto_10
    iget v4, p0, La/b/p/k0;->e:I

    if-ne v4, v7, :cond_19

    move v3, v7

    goto :goto_11

    :cond_19
    if-ne v4, v6, :cond_1a

    goto :goto_11

    :cond_1a
    move v3, v4

    :goto_11
    iget-object v4, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v4, v0}, Landroid/widget/PopupWindow;->setWidth(I)V

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v3}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 18
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const-string v3, "ListPopupWindow"

    const/16 v4, 0x1c

    if-gt v0, v4, :cond_1b

    sget-object v0, La/b/p/k0;->D:Ljava/lang/reflect/Method;

    if-eqz v0, :cond_1c

    :try_start_0
    iget-object v5, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    new-array v6, v1, [Ljava/lang/Object;

    sget-object v8, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    aput-object v8, v6, v2

    invoke-virtual {v0, v5, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_12

    :catch_0
    const-string v0, "Could not call setClipToScreenEnabled() on PopupWindow. Oh well."

    invoke-static {v3, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_12

    :cond_1b
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setIsClippedToScreen(Z)V

    .line 19
    :cond_1c
    :goto_12
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget-boolean v5, p0, La/b/p/k0;->o:Z

    if-nez v5, :cond_1d

    iget-boolean v5, p0, La/b/p/k0;->n:Z

    if-nez v5, :cond_1d

    move v5, v1

    goto :goto_13

    :cond_1d
    move v5, v2

    :goto_13
    invoke-virtual {v0, v5}, Landroid/widget/PopupWindow;->setOutsideTouchable(Z)V

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget-object v5, p0, La/b/p/k0;->v:La/b/p/k0$d;

    invoke-virtual {v0, v5}, Landroid/widget/PopupWindow;->setTouchInterceptor(Landroid/view/View$OnTouchListener;)V

    iget-boolean v0, p0, La/b/p/k0;->l:Z

    if-eqz v0, :cond_1e

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget-boolean v5, p0, La/b/p/k0;->k:Z

    .line 20
    invoke-virtual {v0, v5}, Landroid/widget/PopupWindow;->setOverlapAnchor(Z)V

    .line 21
    :cond_1e
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    if-gt v0, v4, :cond_1f

    sget-object v0, La/b/p/k0;->E:Ljava/lang/reflect/Method;

    if-eqz v0, :cond_20

    :try_start_1
    iget-object v4, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    new-array v5, v1, [Ljava/lang/Object;

    iget-object v6, p0, La/b/p/k0;->A:Landroid/graphics/Rect;

    aput-object v6, v5, v2

    invoke-virtual {v0, v4, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_14

    :catch_1
    move-exception v0

    const-string v2, "Could not invoke setEpicenterBounds on PopupWindow"

    invoke-static {v3, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_14

    :cond_1f
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    iget-object v2, p0, La/b/p/k0;->A:Landroid/graphics/Rect;

    invoke-virtual {v0, v2}, Landroid/widget/PopupWindow;->setEpicenterBounds(Landroid/graphics/Rect;)V

    :cond_20
    :goto_14
    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    .line 22
    iget-object v2, p0, La/b/p/k0;->s:Landroid/view/View;

    .line 23
    iget v3, p0, La/b/p/k0;->g:I

    iget v4, p0, La/b/p/k0;->h:I

    iget v5, p0, La/b/p/k0;->m:I

    .line 24
    invoke-virtual {v0, v2, v3, v4, v5}, Landroid/widget/PopupWindow;->showAsDropDown(Landroid/view/View;III)V

    .line 25
    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v0, v7}, Landroid/widget/ListView;->setSelection(I)V

    iget-boolean v0, p0, La/b/p/k0;->B:Z

    if-eqz v0, :cond_21

    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    invoke-virtual {v0}, La/b/p/f0;->isInTouchMode()Z

    move-result v0

    if-eqz v0, :cond_22

    .line 26
    :cond_21
    iget-object v0, p0, La/b/p/k0;->d:La/b/p/f0;

    if-eqz v0, :cond_22

    invoke-virtual {v0, v1}, La/b/p/f0;->setListSelectionHidden(Z)V

    invoke-virtual {v0}, Landroid/widget/ListView;->requestLayout()V

    .line 27
    :cond_22
    iget-boolean v0, p0, La/b/p/k0;->B:Z

    if-nez v0, :cond_23

    iget-object v0, p0, La/b/p/k0;->y:Landroid/os/Handler;

    iget-object v1, p0, La/b/p/k0;->x:La/b/p/k0$a;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    :cond_23
    :goto_15
    return-void
.end method

.method public j()I
    .locals 1

    iget-boolean v0, p0, La/b/p/k0;->j:Z

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    iget v0, p0, La/b/p/k0;->h:I

    return v0
.end method

.method public l(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, p1}, Landroid/widget/PopupWindow;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    return-void
.end method

.method public m(I)V
    .locals 0

    iput p1, p0, La/b/p/k0;->h:I

    const/4 p1, 0x1

    iput-boolean p1, p0, La/b/p/k0;->j:Z

    return-void
.end method

.method public n()Landroid/graphics/drawable/Drawable;
    .locals 1

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0
.end method

.method public o(Landroid/widget/ListAdapter;)V
    .locals 2

    iget-object v0, p0, La/b/p/k0;->r:Landroid/database/DataSetObserver;

    if-nez v0, :cond_0

    new-instance v0, La/b/p/k0$b;

    invoke-direct {v0, p0}, La/b/p/k0$b;-><init>(La/b/p/k0;)V

    iput-object v0, p0, La/b/p/k0;->r:Landroid/database/DataSetObserver;

    goto :goto_0

    :cond_0
    iget-object v1, p0, La/b/p/k0;->c:Landroid/widget/ListAdapter;

    if-eqz v1, :cond_1

    invoke-interface {v1, v0}, Landroid/widget/ListAdapter;->unregisterDataSetObserver(Landroid/database/DataSetObserver;)V

    :cond_1
    :goto_0
    iput-object p1, p0, La/b/p/k0;->c:Landroid/widget/ListAdapter;

    if-eqz p1, :cond_2

    iget-object v0, p0, La/b/p/k0;->r:Landroid/database/DataSetObserver;

    invoke-interface {p1, v0}, Landroid/widget/ListAdapter;->registerDataSetObserver(Landroid/database/DataSetObserver;)V

    :cond_2
    iget-object p1, p0, La/b/p/k0;->d:La/b/p/f0;

    if-eqz p1, :cond_3

    iget-object v0, p0, La/b/p/k0;->c:Landroid/widget/ListAdapter;

    invoke-virtual {p1, v0}, Landroid/widget/ListView;->setAdapter(Landroid/widget/ListAdapter;)V

    :cond_3
    return-void
.end method

.method public q(Landroid/content/Context;Z)La/b/p/f0;
    .locals 1

    new-instance v0, La/b/p/f0;

    invoke-direct {v0, p1, p2}, La/b/p/f0;-><init>(Landroid/content/Context;Z)V

    return-object v0
.end method

.method public r(I)V
    .locals 2

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    iget-object v0, p0, La/b/p/k0;->z:Landroid/graphics/Rect;

    iget v1, v0, Landroid/graphics/Rect;->left:I

    iget v0, v0, Landroid/graphics/Rect;->right:I

    add-int/2addr v1, v0

    add-int/2addr v1, p1

    iput v1, p0, La/b/p/k0;->f:I

    goto :goto_0

    .line 1
    :cond_0
    iput p1, p0, La/b/p/k0;->f:I

    :goto_0
    return-void
.end method

.method public s(Z)V
    .locals 1

    iput-boolean p1, p0, La/b/p/k0;->B:Z

    iget-object v0, p0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, p1}, Landroid/widget/PopupWindow;->setFocusable(Z)V

    return-void
.end method
