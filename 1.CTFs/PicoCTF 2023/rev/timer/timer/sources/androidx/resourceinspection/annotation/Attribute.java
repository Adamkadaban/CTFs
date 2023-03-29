package androidx.resourceinspection.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.SOURCE)
/* loaded from: classes.dex */
public @interface Attribute {

    @Target({})
    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface IntMap {
        int mask() default 0;

        String name();

        int value();
    }

    IntMap[] intMapping() default {};

    String value();
}
