.class public Landroidx/appcompat/widget/SearchView$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/text/TextWatcher;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/widget/SearchView;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:Landroidx/appcompat/widget/SearchView;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/SearchView;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/widget/SearchView$a;->b:Landroidx/appcompat/widget/SearchView;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public afterTextChanged(Landroid/text/Editable;)V
    .locals 0

    return-void
.end method

.method public beforeTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    return-void
.end method

.method public onTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    iget-object p2, p0, Landroidx/appcompat/widget/SearchView$a;->b:Landroidx/appcompat/widget/SearchView;

    .line 1
    iget-object p3, p2, Landroidx/appcompat/widget/SearchView;->q:Landroidx/appcompat/widget/SearchView$SearchAutoComplete;

    invoke-virtual {p3}, Landroid/widget/AutoCompleteTextView;->getText()Landroid/text/Editable;

    move-result-object p3

    iput-object p3, p2, Landroidx/appcompat/widget/SearchView;->d0:Ljava/lang/CharSequence;

    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p3

    xor-int/lit8 p3, p3, 0x1

    invoke-virtual {p2, p3}, Landroidx/appcompat/widget/SearchView;->F(Z)V

    xor-int/lit8 p3, p3, 0x1

    invoke-virtual {p2, p3}, Landroidx/appcompat/widget/SearchView;->H(Z)V

    invoke-virtual {p2}, Landroidx/appcompat/widget/SearchView;->B()V

    invoke-virtual {p2}, Landroidx/appcompat/widget/SearchView;->E()V

    iget-object p3, p2, Landroidx/appcompat/widget/SearchView;->L:Landroidx/appcompat/widget/SearchView$l;

    if-eqz p3, :cond_0

    iget-object p3, p2, Landroidx/appcompat/widget/SearchView;->c0:Ljava/lang/CharSequence;

    invoke-static {p1, p3}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result p3

    if-nez p3, :cond_0

    iget-object p3, p2, Landroidx/appcompat/widget/SearchView;->L:Landroidx/appcompat/widget/SearchView$l;

    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    move-result-object p4

    invoke-interface {p3, p4}, Landroidx/appcompat/widget/SearchView$l;->b(Ljava/lang/String;)Z

    :cond_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p2, Landroidx/appcompat/widget/SearchView;->c0:Ljava/lang/CharSequence;

    return-void
.end method
