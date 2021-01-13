.class public La/e/c/b;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        La/e/c/b$a;
    }
.end annotation


# instance fields
.field public a:Ljava/lang/String;

.field public b:La/e/c/b$a;

.field public c:I

.field public d:F

.field public e:Ljava/lang/String;

.field public f:Z

.field public g:I


# direct methods
.method public constructor <init>(La/e/c/b;Ljava/lang/Object;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, La/e/c/b;->a:Ljava/lang/String;

    iput-object v0, p0, La/e/c/b;->a:Ljava/lang/String;

    iget-object p1, p1, La/e/c/b;->b:La/e/c/b$a;

    iput-object p1, p0, La/e/c/b;->b:La/e/c/b$a;

    invoke-virtual {p0, p2}, La/e/c/b;->b(Ljava/lang/Object;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;La/e/c/b$a;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La/e/c/b;->a:Ljava/lang/String;

    iput-object p2, p0, La/e/c/b;->b:La/e/c/b$a;

    invoke-virtual {p0, p3}, La/e/c/b;->b(Ljava/lang/Object;)V

    return-void
.end method

.method public static a(Landroid/content/Context;Lorg/xmlpull/v1/XmlPullParser;Ljava/util/HashMap;)V
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lorg/xmlpull/v1/XmlPullParser;",
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "La/e/c/b;",
            ">;)V"
        }
    .end annotation

    sget-object v0, La/e/c/b$a;->h:La/e/c/b$a;

    invoke-static {p1}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    move-result-object p1

    sget-object v1, La/e/c/k;->CustomAttribute:[I

    invoke-virtual {p0, p1, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v4, v2

    move-object v5, v4

    move v6, v3

    :goto_0
    if-ge v6, v1, :cond_9

    invoke-virtual {p1, v6}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v7

    sget v8, La/e/c/k;->CustomAttribute_attributeName:I

    const/4 v9, 0x1

    if-ne v7, v8, :cond_0

    invoke-virtual {p1, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_8

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v7

    if-lez v7, :cond_8

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v3}, Ljava/lang/String;->charAt(I)C

    move-result v8

    invoke-static {v8}, Ljava/lang/Character;->toUpperCase(C)C

    move-result v8

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v9}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    goto/16 :goto_5

    :cond_0
    sget v8, La/e/c/k;->CustomAttribute_customBoolean:I

    if-ne v7, v8, :cond_1

    invoke-virtual {p1, v7, v3}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v4

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    sget-object v5, La/e/c/b$a;->g:La/e/c/b$a;

    goto/16 :goto_5

    :cond_1
    sget v8, La/e/c/k;->CustomAttribute_customColorValue:I

    if-ne v7, v8, :cond_2

    sget-object v4, La/e/c/b$a;->d:La/e/c/b$a;

    goto :goto_1

    :cond_2
    sget v8, La/e/c/k;->CustomAttribute_customColorDrawableValue:I

    if-ne v7, v8, :cond_3

    sget-object v4, La/e/c/b$a;->e:La/e/c/b$a;

    :goto_1
    invoke-virtual {p1, v7, v3}, Landroid/content/res/TypedArray;->getColor(II)I

    move-result v5

    goto :goto_3

    :cond_3
    sget v8, La/e/c/k;->CustomAttribute_customPixelDimension:I

    const/4 v10, 0x0

    if-ne v7, v8, :cond_4

    invoke-virtual {p1, v7, v10}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v4

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v5

    invoke-static {v9, v4, v5}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v4

    goto :goto_2

    :cond_4
    sget v8, La/e/c/k;->CustomAttribute_customDimension:I

    if-ne v7, v8, :cond_5

    invoke-virtual {p1, v7, v10}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v4

    :goto_2
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    move-object v5, v0

    goto :goto_5

    :cond_5
    sget v8, La/e/c/k;->CustomAttribute_customFloatValue:I

    if-ne v7, v8, :cond_6

    sget-object v4, La/e/c/b$a;->c:La/e/c/b$a;

    const/high16 v5, 0x7fc00000    # Float.NaN

    invoke-virtual {p1, v7, v5}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v5

    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v5

    goto :goto_4

    :cond_6
    sget v8, La/e/c/k;->CustomAttribute_customIntegerValue:I

    if-ne v7, v8, :cond_7

    sget-object v4, La/e/c/b$a;->b:La/e/c/b$a;

    const/4 v5, -0x1

    invoke-virtual {p1, v7, v5}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v5

    :goto_3
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    goto :goto_4

    :cond_7
    sget v8, La/e/c/k;->CustomAttribute_customStringValue:I

    if-ne v7, v8, :cond_8

    sget-object v4, La/e/c/b$a;->f:La/e/c/b$a;

    invoke-virtual {p1, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v5

    :goto_4
    move-object v11, v5

    move-object v5, v4

    move-object v4, v11

    :cond_8
    :goto_5
    add-int/lit8 v6, v6, 0x1

    goto/16 :goto_0

    :cond_9
    if-eqz v2, :cond_a

    if-eqz v4, :cond_a

    new-instance p0, La/e/c/b;

    invoke-direct {p0, v2, v5, v4}, La/e/c/b;-><init>(Ljava/lang/String;La/e/c/b$a;Ljava/lang/Object;)V

    invoke-virtual {p2, v2, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_a
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    return-void
.end method


# virtual methods
.method public b(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, La/e/c/b;->b:La/e/c/b$a;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    packed-switch v0, :pswitch_data_0

    goto :goto_0

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iput-boolean p1, p0, La/e/c/b;->f:Z

    goto :goto_0

    :pswitch_1
    check-cast p1, Ljava/lang/String;

    iput-object p1, p0, La/e/c/b;->e:Ljava/lang/String;

    goto :goto_0

    :pswitch_2
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    iput p1, p0, La/e/c/b;->d:F

    goto :goto_0

    :pswitch_3
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iput p1, p0, La/e/c/b;->c:I

    goto :goto_0

    :pswitch_4
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iput p1, p0, La/e/c/b;->g:I

    :goto_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_4
        :pswitch_4
        :pswitch_1
        :pswitch_0
        :pswitch_2
    .end packed-switch
.end method
