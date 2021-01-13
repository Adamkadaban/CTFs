.class public final La/b/o/i/q;
.super La/b/o/i/k;
.source ""

# interfaces
.implements Landroid/widget/PopupWindow$OnDismissListener;
.implements Landroid/widget/AdapterView$OnItemClickListener;
.implements La/b/o/i/m;
.implements Landroid/view/View$OnKeyListener;


# static fields
.field public static final w:I


# instance fields
.field public final c:Landroid/content/Context;

.field public final d:La/b/o/i/g;

.field public final e:La/b/o/i/f;

.field public final f:Z

.field public final g:I

.field public final h:I

.field public final i:I

.field public final j:La/b/p/m0;

.field public final k:Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;

.field public final l:Landroid/view/View$OnAttachStateChangeListener;

.field public m:Landroid/widget/PopupWindow$OnDismissListener;

.field public n:Landroid/view/View;

.field public o:Landroid/view/View;

.field public p:La/b/o/i/m$a;

.field public q:Landroid/view/ViewTreeObserver;

.field public r:Z

.field public s:Z

.field public t:I

.field public u:I

.field public v:Z


# direct methods
.method public static constructor <clinit>()V
    .locals 1

    sget v0, La/b/g;->abc_popup_menu_item_layout:I

    sput v0, La/b/o/i/q;->w:I

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;La/b/o/i/g;Landroid/view/View;IIZ)V
    .locals 3

    invoke-direct {p0}, La/b/o/i/k;-><init>()V

    new-instance v0, La/b/o/i/q$a;

    invoke-direct {v0, p0}, La/b/o/i/q$a;-><init>(La/b/o/i/q;)V

    iput-object v0, p0, La/b/o/i/q;->k:Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;

    new-instance v0, La/b/o/i/q$b;

    invoke-direct {v0, p0}, La/b/o/i/q$b;-><init>(La/b/o/i/q;)V

    iput-object v0, p0, La/b/o/i/q;->l:Landroid/view/View$OnAttachStateChangeListener;

    const/4 v0, 0x0

    iput v0, p0, La/b/o/i/q;->u:I

    iput-object p1, p0, La/b/o/i/q;->c:Landroid/content/Context;

    iput-object p2, p0, La/b/o/i/q;->d:La/b/o/i/g;

    iput-boolean p6, p0, La/b/o/i/q;->f:Z

    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p6

    new-instance v0, La/b/o/i/f;

    iget-boolean v1, p0, La/b/o/i/q;->f:Z

    sget v2, La/b/o/i/q;->w:I

    invoke-direct {v0, p2, p6, v1, v2}, La/b/o/i/f;-><init>(La/b/o/i/g;Landroid/view/LayoutInflater;ZI)V

    iput-object v0, p0, La/b/o/i/q;->e:La/b/o/i/f;

    iput p4, p0, La/b/o/i/q;->h:I

    iput p5, p0, La/b/o/i/q;->i:I

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p4

    invoke-virtual {p4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object p5

    iget p5, p5, Landroid/util/DisplayMetrics;->widthPixels:I

    div-int/lit8 p5, p5, 0x2

    sget p6, La/b/d;->abc_config_prefDialogWidth:I

    invoke-virtual {p4, p6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p4

    invoke-static {p5, p4}, Ljava/lang/Math;->max(II)I

    move-result p4

    iput p4, p0, La/b/o/i/q;->g:I

    iput-object p3, p0, La/b/o/i/q;->n:Landroid/view/View;

    new-instance p3, La/b/p/m0;

    iget-object p4, p0, La/b/o/i/q;->c:Landroid/content/Context;

    iget p5, p0, La/b/o/i/q;->h:I

    iget p6, p0, La/b/o/i/q;->i:I

    const/4 v0, 0x0

    invoke-direct {p3, p4, v0, p5, p6}, La/b/p/m0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    iput-object p3, p0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {p2, p0, p1}, La/b/o/i/g;->b(La/b/o/i/m;Landroid/content/Context;)V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    iget-boolean v0, p0, La/b/o/i/q;->r:Z

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {v0}, La/b/p/k0;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public b(La/b/o/i/g;Z)V
    .locals 1

    iget-object v0, p0, La/b/o/i/q;->d:La/b/o/i/g;

    if-eq p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, La/b/o/i/q;->dismiss()V

    iget-object v0, p0, La/b/o/i/q;->p:La/b/o/i/m$a;

    if-eqz v0, :cond_1

    invoke-interface {v0, p1, p2}, La/b/o/i/m$a;->b(La/b/o/i/g;Z)V

    :cond_1
    return-void
.end method

.method public d(La/b/o/i/m$a;)V
    .locals 0

    iput-object p1, p0, La/b/o/i/q;->p:La/b/o/i/m$a;

    return-void
.end method

.method public dismiss()V
    .locals 1

    invoke-virtual {p0}, La/b/o/i/q;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {v0}, La/b/p/k0;->dismiss()V

    :cond_0
    return-void
.end method

.method public e()Landroid/widget/ListView;
    .locals 1

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 1
    iget-object v0, v0, La/b/p/k0;->d:La/b/p/f0;

    return-object v0
.end method

.method public f(La/b/o/i/r;)Z
    .locals 9

    invoke-virtual {p1}, La/b/o/i/g;->hasVisibleItems()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_6

    new-instance v0, La/b/o/i/l;

    iget-object v3, p0, La/b/o/i/q;->c:Landroid/content/Context;

    iget-object v5, p0, La/b/o/i/q;->o:Landroid/view/View;

    iget-boolean v6, p0, La/b/o/i/q;->f:Z

    iget v7, p0, La/b/o/i/q;->h:I

    iget v8, p0, La/b/o/i/q;->i:I

    move-object v2, v0

    move-object v4, p1

    invoke-direct/range {v2 .. v8}, La/b/o/i/l;-><init>(Landroid/content/Context;La/b/o/i/g;Landroid/view/View;ZII)V

    iget-object v2, p0, La/b/o/i/q;->p:La/b/o/i/m$a;

    invoke-virtual {v0, v2}, La/b/o/i/l;->d(La/b/o/i/m$a;)V

    invoke-static {p1}, La/b/o/i/k;->v(La/b/o/i/g;)Z

    move-result v2

    .line 1
    iput-boolean v2, v0, La/b/o/i/l;->h:Z

    iget-object v3, v0, La/b/o/i/l;->j:La/b/o/i/k;

    if-eqz v3, :cond_0

    invoke-virtual {v3, v2}, La/b/o/i/k;->p(Z)V

    .line 2
    :cond_0
    iget-object v2, p0, La/b/o/i/q;->m:Landroid/widget/PopupWindow$OnDismissListener;

    .line 3
    iput-object v2, v0, La/b/o/i/l;->k:Landroid/widget/PopupWindow$OnDismissListener;

    const/4 v2, 0x0

    .line 4
    iput-object v2, p0, La/b/o/i/q;->m:Landroid/widget/PopupWindow$OnDismissListener;

    iget-object v2, p0, La/b/o/i/q;->d:La/b/o/i/g;

    invoke-virtual {v2, v1}, La/b/o/i/g;->c(Z)V

    iget-object v2, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 5
    iget v3, v2, La/b/p/k0;->g:I

    .line 6
    iget-boolean v4, v2, La/b/p/k0;->j:Z

    if-nez v4, :cond_1

    move v2, v1

    goto :goto_0

    :cond_1
    iget v2, v2, La/b/p/k0;->h:I

    .line 7
    :goto_0
    iget v4, p0, La/b/o/i/q;->u:I

    iget-object v5, p0, La/b/o/i/q;->n:Landroid/view/View;

    invoke-static {v5}, La/f/j/k;->f(Landroid/view/View;)I

    move-result v5

    invoke-static {v4, v5}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    move-result v4

    and-int/lit8 v4, v4, 0x7

    const/4 v5, 0x5

    if-ne v4, v5, :cond_2

    iget-object v4, p0, La/b/o/i/q;->n:Landroid/view/View;

    invoke-virtual {v4}, Landroid/view/View;->getWidth()I

    move-result v4

    add-int/2addr v3, v4

    .line 8
    :cond_2
    invoke-virtual {v0}, La/b/o/i/l;->b()Z

    move-result v4

    const/4 v5, 0x1

    if-eqz v4, :cond_3

    goto :goto_1

    :cond_3
    iget-object v4, v0, La/b/o/i/l;->f:Landroid/view/View;

    if-nez v4, :cond_4

    move v0, v1

    goto :goto_2

    :cond_4
    invoke-virtual {v0, v3, v2, v5, v5}, La/b/o/i/l;->e(IIZZ)V

    :goto_1
    move v0, v5

    :goto_2
    if-eqz v0, :cond_6

    .line 9
    iget-object v0, p0, La/b/o/i/q;->p:La/b/o/i/m$a;

    if-eqz v0, :cond_5

    invoke-interface {v0, p1}, La/b/o/i/m$a;->c(La/b/o/i/g;)Z

    :cond_5
    return v5

    :cond_6
    return v1
.end method

.method public g()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public h(Z)V
    .locals 0

    const/4 p1, 0x0

    iput-boolean p1, p0, La/b/o/i/q;->s:Z

    iget-object p1, p0, La/b/o/i/q;->e:La/b/o/i/f;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, La/b/o/i/f;->notifyDataSetChanged()V

    :cond_0
    return-void
.end method

.method public i()V
    .locals 7

    .line 1
    invoke-virtual {p0}, La/b/o/i/q;->a()Z

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    goto/16 :goto_3

    :cond_0
    iget-boolean v0, p0, La/b/o/i/q;->r:Z

    const/4 v2, 0x0

    if-nez v0, :cond_9

    iget-object v0, p0, La/b/o/i/q;->n:Landroid/view/View;

    if-nez v0, :cond_1

    goto/16 :goto_2

    :cond_1
    iput-object v0, p0, La/b/o/i/q;->o:Landroid/view/View;

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 2
    iget-object v0, v0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, p0}, Landroid/widget/PopupWindow;->setOnDismissListener(Landroid/widget/PopupWindow$OnDismissListener;)V

    .line 3
    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 4
    iput-object p0, v0, La/b/p/k0;->t:Landroid/widget/AdapterView$OnItemClickListener;

    .line 5
    invoke-virtual {v0, v1}, La/b/p/k0;->s(Z)V

    iget-object v0, p0, La/b/o/i/q;->o:Landroid/view/View;

    iget-object v3, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    if-nez v3, :cond_2

    move v3, v1

    goto :goto_0

    :cond_2
    move v3, v2

    :goto_0
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v4

    iput-object v4, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    if-eqz v3, :cond_3

    iget-object v3, p0, La/b/o/i/q;->k:Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;

    invoke-virtual {v4, v3}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    :cond_3
    iget-object v3, p0, La/b/o/i/q;->l:Landroid/view/View$OnAttachStateChangeListener;

    invoke-virtual {v0, v3}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    iget-object v3, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 6
    iput-object v0, v3, La/b/p/k0;->s:Landroid/view/View;

    .line 7
    iget v0, p0, La/b/o/i/q;->u:I

    .line 8
    iput v0, v3, La/b/p/k0;->m:I

    .line 9
    iget-boolean v0, p0, La/b/o/i/q;->s:Z

    const/4 v3, 0x0

    if-nez v0, :cond_4

    iget-object v0, p0, La/b/o/i/q;->e:La/b/o/i/f;

    iget-object v4, p0, La/b/o/i/q;->c:Landroid/content/Context;

    iget v5, p0, La/b/o/i/q;->g:I

    invoke-static {v0, v3, v4, v5}, La/b/o/i/k;->n(Landroid/widget/ListAdapter;Landroid/view/ViewGroup;Landroid/content/Context;I)I

    move-result v0

    iput v0, p0, La/b/o/i/q;->t:I

    iput-boolean v1, p0, La/b/o/i/q;->s:Z

    :cond_4
    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    iget v4, p0, La/b/o/i/q;->t:I

    invoke-virtual {v0, v4}, La/b/p/k0;->r(I)V

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    const/4 v4, 0x2

    .line 10
    iget-object v0, v0, La/b/p/k0;->C:Landroid/widget/PopupWindow;

    invoke-virtual {v0, v4}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    .line 11
    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 12
    iget-object v4, p0, La/b/o/i/k;->b:Landroid/graphics/Rect;

    if-eqz v0, :cond_8

    if-eqz v4, :cond_5

    .line 13
    new-instance v5, Landroid/graphics/Rect;

    invoke-direct {v5, v4}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    goto :goto_1

    :cond_5
    move-object v5, v3

    :goto_1
    iput-object v5, v0, La/b/p/k0;->A:Landroid/graphics/Rect;

    .line 14
    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {v0}, La/b/p/k0;->i()V

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 15
    iget-object v0, v0, La/b/p/k0;->d:La/b/p/f0;

    .line 16
    invoke-virtual {v0, p0}, Landroid/widget/ListView;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    iget-boolean v4, p0, La/b/o/i/q;->v:Z

    if-eqz v4, :cond_7

    iget-object v4, p0, La/b/o/i/q;->d:La/b/o/i/g;

    .line 17
    iget-object v4, v4, La/b/o/i/g;->m:Ljava/lang/CharSequence;

    if-eqz v4, :cond_7

    .line 18
    iget-object v4, p0, La/b/o/i/q;->c:Landroid/content/Context;

    invoke-static {v4}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v4

    sget v5, La/b/g;->abc_popup_menu_header_item_layout:I

    invoke-virtual {v4, v5, v0, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object v4

    check-cast v4, Landroid/widget/FrameLayout;

    const v5, 0x1020016

    invoke-virtual {v4, v5}, Landroid/widget/FrameLayout;->findViewById(I)Landroid/view/View;

    move-result-object v5

    check-cast v5, Landroid/widget/TextView;

    if-eqz v5, :cond_6

    iget-object v6, p0, La/b/o/i/q;->d:La/b/o/i/g;

    .line 19
    iget-object v6, v6, La/b/o/i/g;->m:Ljava/lang/CharSequence;

    .line 20
    invoke-virtual {v5, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_6
    invoke-virtual {v4, v2}, Landroid/widget/FrameLayout;->setEnabled(Z)V

    invoke-virtual {v0, v4, v3, v2}, Landroid/widget/ListView;->addHeaderView(Landroid/view/View;Ljava/lang/Object;Z)V

    :cond_7
    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    iget-object v2, p0, La/b/o/i/q;->e:La/b/o/i/f;

    invoke-virtual {v0, v2}, La/b/p/k0;->o(Landroid/widget/ListAdapter;)V

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    invoke-virtual {v0}, La/b/p/k0;->i()V

    goto :goto_3

    .line 21
    :cond_8
    throw v3

    :cond_9
    :goto_2
    move v1, v2

    :goto_3
    if-eqz v1, :cond_a

    return-void

    .line 22
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "StandardMenuPopup cannot be used without an anchor"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public l(La/b/o/i/g;)V
    .locals 0

    return-void
.end method

.method public o(Landroid/view/View;)V
    .locals 0

    iput-object p1, p0, La/b/o/i/q;->n:Landroid/view/View;

    return-void
.end method

.method public onDismiss()V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, La/b/o/i/q;->r:Z

    iget-object v1, p0, La/b/o/i/q;->d:La/b/o/i/g;

    .line 1
    invoke-virtual {v1, v0}, La/b/o/i/g;->c(Z)V

    .line 2
    iget-object v0, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, La/b/o/i/q;->o:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v0

    iput-object v0, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    :cond_0
    iget-object v0, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    iget-object v1, p0, La/b/o/i/q;->k:Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;

    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    const/4 v0, 0x0

    iput-object v0, p0, La/b/o/i/q;->q:Landroid/view/ViewTreeObserver;

    :cond_1
    iget-object v0, p0, La/b/o/i/q;->o:Landroid/view/View;

    iget-object v1, p0, La/b/o/i/q;->l:Landroid/view/View$OnAttachStateChangeListener;

    invoke-virtual {v0, v1}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    iget-object v0, p0, La/b/o/i/q;->m:Landroid/widget/PopupWindow$OnDismissListener;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Landroid/widget/PopupWindow$OnDismissListener;->onDismiss()V

    :cond_2
    return-void
.end method

.method public onKey(Landroid/view/View;ILandroid/view/KeyEvent;)Z
    .locals 0

    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    move-result p1

    const/4 p3, 0x1

    if-ne p1, p3, :cond_0

    const/16 p1, 0x52

    if-ne p2, p1, :cond_0

    invoke-virtual {p0}, La/b/o/i/q;->dismiss()V

    return p3

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public p(Z)V
    .locals 1

    iget-object v0, p0, La/b/o/i/q;->e:La/b/o/i/f;

    .line 1
    iput-boolean p1, v0, La/b/o/i/f;->d:Z

    return-void
.end method

.method public q(I)V
    .locals 0

    iput p1, p0, La/b/o/i/q;->u:I

    return-void
.end method

.method public r(I)V
    .locals 1

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 1
    iput p1, v0, La/b/p/k0;->g:I

    return-void
.end method

.method public s(Landroid/widget/PopupWindow$OnDismissListener;)V
    .locals 0

    iput-object p1, p0, La/b/o/i/q;->m:Landroid/widget/PopupWindow$OnDismissListener;

    return-void
.end method

.method public t(Z)V
    .locals 0

    iput-boolean p1, p0, La/b/o/i/q;->v:Z

    return-void
.end method

.method public u(I)V
    .locals 1

    iget-object v0, p0, La/b/o/i/q;->j:La/b/p/m0;

    .line 1
    iput p1, v0, La/b/p/k0;->h:I

    const/4 p1, 0x1

    iput-boolean p1, v0, La/b/p/k0;->j:Z

    return-void
.end method
