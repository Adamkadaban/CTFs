.class public La/f/k/a$b;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = La/f/k/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "b"
.end annotation


# instance fields
.field public final synthetic b:La/f/k/a;


# direct methods
.method public constructor <init>(La/f/k/a;)V
    .locals 0

    iput-object p1, p0, La/f/k/a$b;->b:La/f/k/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 14

    iget-object v0, p0, La/f/k/a$b;->b:La/f/k/a;

    iget-boolean v1, v0, La/f/k/a;->p:Z

    if-nez v1, :cond_0

    return-void

    :cond_0
    iget-boolean v1, v0, La/f/k/a;->n:Z

    const/4 v2, 0x0

    const/4 v3, 0x0

    if-eqz v1, :cond_2

    iput-boolean v3, v0, La/f/k/a;->n:Z

    iget-object v0, v0, La/f/k/a;->b:La/f/k/a$a;

    if-eqz v0, :cond_1

    .line 1
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    move-result-wide v1

    iput-wide v1, v0, La/f/k/a$a;->e:J

    const-wide/16 v4, -0x1

    iput-wide v4, v0, La/f/k/a$a;->i:J

    iput-wide v1, v0, La/f/k/a$a;->f:J

    const/high16 v1, 0x3f000000    # 0.5f

    iput v1, v0, La/f/k/a$a;->j:F

    iput v3, v0, La/f/k/a$a;->g:I

    iput v3, v0, La/f/k/a$a;->h:I

    goto :goto_0

    :cond_1
    throw v2

    .line 2
    :cond_2
    :goto_0
    iget-object v0, p0, La/f/k/a$b;->b:La/f/k/a;

    iget-object v0, v0, La/f/k/a;->b:La/f/k/a$a;

    .line 3
    iget-wide v1, v0, La/f/k/a$a;->i:J

    const-wide/16 v4, 0x0

    cmp-long v1, v1, v4

    if-lez v1, :cond_3

    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    move-result-wide v1

    iget-wide v6, v0, La/f/k/a$a;->i:J

    iget v8, v0, La/f/k/a$a;->k:I

    int-to-long v8, v8

    add-long/2addr v6, v8

    cmp-long v1, v1, v6

    if-lez v1, :cond_3

    const/4 v1, 0x1

    goto :goto_1

    :cond_3
    move v1, v3

    :goto_1
    if-nez v1, :cond_7

    .line 4
    iget-object v1, p0, La/f/k/a$b;->b:La/f/k/a;

    invoke-virtual {v1}, La/f/k/a;->e()Z

    move-result v1

    if-nez v1, :cond_4

    goto :goto_2

    :cond_4
    iget-object v1, p0, La/f/k/a$b;->b:La/f/k/a;

    iget-boolean v2, v1, La/f/k/a;->o:Z

    if-eqz v2, :cond_5

    iput-boolean v3, v1, La/f/k/a;->o:Z

    .line 5
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    move-result-wide v8

    const/4 v10, 0x3

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-wide v6, v8

    invoke-static/range {v6 .. v13}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    move-result-object v2

    iget-object v1, v1, La/f/k/a;->d:Landroid/view/View;

    invoke-virtual {v1, v2}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    invoke-virtual {v2}, Landroid/view/MotionEvent;->recycle()V

    .line 6
    :cond_5
    iget-wide v1, v0, La/f/k/a$a;->f:J

    cmp-long v1, v1, v4

    if-eqz v1, :cond_6

    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, La/f/k/a$a;->a(J)F

    move-result v3

    const/high16 v4, -0x3f800000    # -4.0f

    mul-float/2addr v4, v3

    mul-float/2addr v4, v3

    const/high16 v5, 0x40800000    # 4.0f

    mul-float/2addr v3, v5

    add-float/2addr v3, v4

    iget-wide v4, v0, La/f/k/a$a;->f:J

    sub-long v4, v1, v4

    iput-wide v1, v0, La/f/k/a$a;->f:J

    long-to-float v1, v4

    mul-float/2addr v1, v3

    iget v2, v0, La/f/k/a$a;->c:F

    mul-float/2addr v2, v1

    float-to-int v2, v2

    iput v2, v0, La/f/k/a$a;->g:I

    iget v2, v0, La/f/k/a$a;->d:F

    mul-float/2addr v1, v2

    float-to-int v1, v1

    iput v1, v0, La/f/k/a$a;->h:I

    .line 7
    iget-object v0, p0, La/f/k/a$b;->b:La/f/k/a;

    check-cast v0, La/f/k/c;

    .line 8
    iget-object v0, v0, La/f/k/c;->s:Landroid/widget/ListView;

    .line 9
    invoke-virtual {v0, v1}, Landroid/widget/ListView;->scrollListBy(I)V

    .line 10
    iget-object v0, p0, La/f/k/a$b;->b:La/f/k/a;

    iget-object v0, v0, La/f/k/a;->d:Landroid/view/View;

    invoke-static {v0, p0}, La/f/j/k;->q(Landroid/view/View;Ljava/lang/Runnable;)V

    return-void

    .line 11
    :cond_6
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "Cannot compute scroll delta before calling start()"

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 12
    :cond_7
    :goto_2
    iget-object v0, p0, La/f/k/a$b;->b:La/f/k/a;

    iput-boolean v3, v0, La/f/k/a;->p:Z

    return-void
.end method
