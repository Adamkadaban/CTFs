.class public La/b/o/i/j;
.super La/b/o/i/c;
.source ""

# interfaces
.implements Landroid/view/MenuItem;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/b/o/i/j$c;,
        La/b/o/i/j$b;,
        La/b/o/i/j$a;,
        La/b/o/i/j$d;,
        La/b/o/i/j$e;
    }
.end annotation


# instance fields
.field public final d:La/f/f/a/b;

.field public e:Ljava/lang/reflect/Method;


# direct methods
.method public constructor <init>(Landroid/content/Context;La/f/f/a/b;)V
    .locals 0

    invoke-direct {p0, p1}, La/b/o/i/c;-><init>(Landroid/content/Context;)V

    if-eqz p2, :cond_0

    iput-object p2, p0, La/b/o/i/j;->d:La/f/f/a/b;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Wrapped Object can not be null."

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public collapseActionView()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->collapseActionView()Z

    move-result v0

    return v0
.end method

.method public expandActionView()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->expandActionView()Z

    move-result v0

    return v0
.end method

.method public getActionProvider()Landroid/view/ActionProvider;
    .locals 2

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->a()La/f/j/b;

    move-result-object v0

    instance-of v1, v0, La/b/o/i/j$a;

    if-eqz v1, :cond_0

    check-cast v0, La/b/o/i/j$a;

    iget-object v0, v0, La/b/o/i/j$a;->b:Landroid/view/ActionProvider;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public getActionView()Landroid/view/View;
    .locals 2

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getActionView()Landroid/view/View;

    move-result-object v0

    instance-of v1, v0, La/b/o/i/j$c;

    if-eqz v1, :cond_0

    check-cast v0, La/b/o/i/j$c;

    .line 1
    iget-object v0, v0, La/b/o/i/j$c;->b:Landroid/view/CollapsibleActionView;

    check-cast v0, Landroid/view/View;

    :cond_0
    return-object v0
.end method

.method public getAlphabeticModifiers()I
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getAlphabeticModifiers()I

    move-result v0

    return v0
.end method

.method public getAlphabeticShortcut()C
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getAlphabeticShortcut()C

    move-result v0

    return v0
.end method

.method public getContentDescription()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getContentDescription()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public getGroupId()I
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getGroupId()I

    move-result v0

    return v0
.end method

.method public getIcon()Landroid/graphics/drawable/Drawable;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getIcon()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0
.end method

.method public getIconTintList()Landroid/content/res/ColorStateList;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getIconTintList()Landroid/content/res/ColorStateList;

    move-result-object v0

    return-object v0
.end method

.method public getIconTintMode()Landroid/graphics/PorterDuff$Mode;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getIconTintMode()Landroid/graphics/PorterDuff$Mode;

    move-result-object v0

    return-object v0
.end method

.method public getIntent()Landroid/content/Intent;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getIntent()Landroid/content/Intent;

    move-result-object v0

    return-object v0
.end method

.method public getItemId()I
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    return v0
.end method

.method public getMenuInfo()Landroid/view/ContextMenu$ContextMenuInfo;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getMenuInfo()Landroid/view/ContextMenu$ContextMenuInfo;

    move-result-object v0

    return-object v0
.end method

.method public getNumericModifiers()I
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getNumericModifiers()I

    move-result v0

    return v0
.end method

.method public getNumericShortcut()C
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getNumericShortcut()C

    move-result v0

    return v0
.end method

.method public getOrder()I
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getOrder()I

    move-result v0

    return v0
.end method

.method public getSubMenu()Landroid/view/SubMenu;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getSubMenu()Landroid/view/SubMenu;

    move-result-object v0

    invoke-virtual {p0, v0}, La/b/o/i/c;->d(Landroid/view/SubMenu;)Landroid/view/SubMenu;

    move-result-object v0

    return-object v0
.end method

.method public getTitle()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getTitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public getTitleCondensed()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->getTitleCondensed()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public getTooltipText()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->getTooltipText()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public hasSubMenu()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->hasSubMenu()Z

    move-result v0

    return v0
.end method

.method public isActionViewExpanded()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, La/f/f/a/b;->isActionViewExpanded()Z

    move-result v0

    return v0
.end method

.method public isCheckable()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->isCheckable()Z

    move-result v0

    return v0
.end method

.method public isChecked()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->isChecked()Z

    move-result v0

    return v0
.end method

.method public isEnabled()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->isEnabled()Z

    move-result v0

    return v0
.end method

.method public isVisible()Z
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0}, Landroid/view/MenuItem;->isVisible()Z

    move-result v0

    return v0
.end method

.method public setActionProvider(Landroid/view/ActionProvider;)Landroid/view/MenuItem;
    .locals 2

    new-instance v0, La/b/o/i/j$b;

    iget-object v1, p0, La/b/o/i/c;->a:Landroid/content/Context;

    invoke-direct {v0, p0, v1, p1}, La/b/o/i/j$b;-><init>(La/b/o/i/j;Landroid/content/Context;Landroid/view/ActionProvider;)V

    iget-object v1, p0, La/b/o/i/j;->d:La/f/f/a/b;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-interface {v1, v0}, La/f/f/a/b;->b(La/f/j/b;)La/f/f/a/b;

    return-object p0
.end method

.method public setActionView(I)Landroid/view/MenuItem;
    .locals 2

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setActionView(I)Landroid/view/MenuItem;

    iget-object p1, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {p1}, La/f/f/a/b;->getActionView()Landroid/view/View;

    move-result-object p1

    instance-of v0, p1, Landroid/view/CollapsibleActionView;

    if-eqz v0, :cond_0

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    new-instance v1, La/b/o/i/j$c;

    invoke-direct {v1, p1}, La/b/o/i/j$c;-><init>(Landroid/view/View;)V

    invoke-interface {v0, v1}, La/f/f/a/b;->setActionView(Landroid/view/View;)Landroid/view/MenuItem;

    :cond_0
    return-object p0
.end method

.method public setActionView(Landroid/view/View;)Landroid/view/MenuItem;
    .locals 1

    instance-of v0, p1, Landroid/view/CollapsibleActionView;

    if-eqz v0, :cond_0

    new-instance v0, La/b/o/i/j$c;

    invoke-direct {v0, p1}, La/b/o/i/j$c;-><init>(Landroid/view/View;)V

    move-object p1, v0

    :cond_0
    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setActionView(Landroid/view/View;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setAlphabeticShortcut(C)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setAlphabeticShortcut(C)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setAlphabeticShortcut(CI)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1, p2}, La/f/f/a/b;->setAlphabeticShortcut(CI)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setCheckable(Z)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setCheckable(Z)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setChecked(Z)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setChecked(Z)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setContentDescription(Ljava/lang/CharSequence;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setContentDescription(Ljava/lang/CharSequence;)La/f/f/a/b;

    return-object p0
.end method

.method public setEnabled(Z)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setEnabled(Z)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setIcon(I)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setIcon(I)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setIcon(Landroid/graphics/drawable/Drawable;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setIcon(Landroid/graphics/drawable/Drawable;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setIconTintList(Landroid/content/res/ColorStateList;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setIconTintList(Landroid/content/res/ColorStateList;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setIconTintMode(Landroid/graphics/PorterDuff$Mode;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setIconTintMode(Landroid/graphics/PorterDuff$Mode;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setIntent(Landroid/content/Intent;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setIntent(Landroid/content/Intent;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setNumericShortcut(C)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setNumericShortcut(C)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setNumericShortcut(CI)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1, p2}, La/f/f/a/b;->setNumericShortcut(CI)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setOnActionExpandListener(Landroid/view/MenuItem$OnActionExpandListener;)Landroid/view/MenuItem;
    .locals 2

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    if-eqz p1, :cond_0

    new-instance v1, La/b/o/i/j$d;

    invoke-direct {v1, p0, p1}, La/b/o/i/j$d;-><init>(La/b/o/i/j;Landroid/view/MenuItem$OnActionExpandListener;)V

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-interface {v0, v1}, Landroid/view/MenuItem;->setOnActionExpandListener(Landroid/view/MenuItem$OnActionExpandListener;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setOnMenuItemClickListener(Landroid/view/MenuItem$OnMenuItemClickListener;)Landroid/view/MenuItem;
    .locals 2

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    if-eqz p1, :cond_0

    new-instance v1, La/b/o/i/j$e;

    invoke-direct {v1, p0, p1}, La/b/o/i/j$e;-><init>(La/b/o/i/j;Landroid/view/MenuItem$OnMenuItemClickListener;)V

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-interface {v0, v1}, Landroid/view/MenuItem;->setOnMenuItemClickListener(Landroid/view/MenuItem$OnMenuItemClickListener;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setShortcut(CC)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1, p2}, Landroid/view/MenuItem;->setShortcut(CC)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setShortcut(CCII)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1, p2, p3, p4}, La/f/f/a/b;->setShortcut(CCII)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setShowAsAction(I)V
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setShowAsAction(I)V

    return-void
.end method

.method public setShowAsActionFlags(I)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setShowAsActionFlags(I)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setTitle(I)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setTitle(I)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setTitle(Ljava/lang/CharSequence;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setTitle(Ljava/lang/CharSequence;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setTitleCondensed(Ljava/lang/CharSequence;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setTitleCondensed(Ljava/lang/CharSequence;)Landroid/view/MenuItem;

    return-object p0
.end method

.method public setTooltipText(Ljava/lang/CharSequence;)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, La/f/f/a/b;->setTooltipText(Ljava/lang/CharSequence;)La/f/f/a/b;

    return-object p0
.end method

.method public setVisible(Z)Landroid/view/MenuItem;
    .locals 1

    iget-object v0, p0, La/b/o/i/j;->d:La/f/f/a/b;

    invoke-interface {v0, p1}, Landroid/view/MenuItem;->setVisible(Z)Landroid/view/MenuItem;

    move-result-object p1

    return-object p1
.end method
