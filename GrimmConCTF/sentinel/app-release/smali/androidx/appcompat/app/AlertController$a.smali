.class public Landroidx/appcompat/app/AlertController$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/app/AlertController;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:Landroidx/appcompat/app/AlertController;


# direct methods
.method public constructor <init>(Landroidx/appcompat/app/AlertController;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/app/AlertController$a;->b:Landroidx/appcompat/app/AlertController;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/app/AlertController$a;->b:Landroidx/appcompat/app/AlertController;

    iget-object v1, v0, Landroidx/appcompat/app/AlertController;->o:Landroid/widget/Button;

    if-ne p1, v1, :cond_0

    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->q:Landroid/os/Message;

    if-eqz v0, :cond_0

    :goto_0
    invoke-static {v0}, Landroid/os/Message;->obtain(Landroid/os/Message;)Landroid/os/Message;

    move-result-object p1

    goto :goto_1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/app/AlertController$a;->b:Landroidx/appcompat/app/AlertController;

    iget-object v1, v0, Landroidx/appcompat/app/AlertController;->s:Landroid/widget/Button;

    if-ne p1, v1, :cond_1

    iget-object v0, v0, Landroidx/appcompat/app/AlertController;->u:Landroid/os/Message;

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/app/AlertController$a;->b:Landroidx/appcompat/app/AlertController;

    iget-object v1, v0, Landroidx/appcompat/app/AlertController;->w:Landroid/widget/Button;

    if-ne p1, v1, :cond_2

    iget-object p1, v0, Landroidx/appcompat/app/AlertController;->y:Landroid/os/Message;

    if-eqz p1, :cond_2

    invoke-static {p1}, Landroid/os/Message;->obtain(Landroid/os/Message;)Landroid/os/Message;

    move-result-object p1

    goto :goto_1

    :cond_2
    const/4 p1, 0x0

    :goto_1
    if-eqz p1, :cond_3

    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    :cond_3
    iget-object p1, p0, Landroidx/appcompat/app/AlertController$a;->b:Landroidx/appcompat/app/AlertController;

    iget-object v0, p1, Landroidx/appcompat/app/AlertController;->R:Landroid/os/Handler;

    const/4 v1, 0x1

    iget-object p1, p1, Landroidx/appcompat/app/AlertController;->b:La/b/k/n;

    invoke-virtual {v0, v1, p1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    return-void
.end method
