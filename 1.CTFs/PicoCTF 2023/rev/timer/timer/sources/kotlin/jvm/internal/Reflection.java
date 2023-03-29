package kotlin.jvm.internal;

import java.util.Arrays;
import java.util.Collections;
import kotlin.collections.ArraysKt;
import kotlin.reflect.KClass;
import kotlin.reflect.KClassifier;
import kotlin.reflect.KDeclarationContainer;
import kotlin.reflect.KFunction;
import kotlin.reflect.KMutableProperty0;
import kotlin.reflect.KMutableProperty1;
import kotlin.reflect.KMutableProperty2;
import kotlin.reflect.KProperty0;
import kotlin.reflect.KProperty1;
import kotlin.reflect.KProperty2;
import kotlin.reflect.KType;
import kotlin.reflect.KTypeParameter;
import kotlin.reflect.KTypeProjection;
import kotlin.reflect.KVariance;
/* loaded from: classes.dex */
public class Reflection {
    private static final KClass[] EMPTY_K_CLASS_ARRAY;
    static final String REFLECTION_NOT_AVAILABLE = " (Kotlin reflection is not available)";
    private static final ReflectionFactory factory;

    static {
        ReflectionFactory impl;
        try {
            Class<?> implClass = Class.forName("kotlin.reflect.jvm.internal.ReflectionFactoryImpl");
            impl = (ReflectionFactory) implClass.newInstance();
        } catch (ClassCastException e) {
            impl = null;
        } catch (ClassNotFoundException e2) {
            impl = null;
        } catch (IllegalAccessException e3) {
            impl = null;
        } catch (InstantiationException e4) {
            impl = null;
        }
        factory = impl != null ? impl : new ReflectionFactory();
        EMPTY_K_CLASS_ARRAY = new KClass[0];
    }

    public static KClass createKotlinClass(Class javaClass) {
        return factory.createKotlinClass(javaClass);
    }

    public static KClass createKotlinClass(Class javaClass, String internalName) {
        return factory.createKotlinClass(javaClass, internalName);
    }

    public static KDeclarationContainer getOrCreateKotlinPackage(Class javaClass) {
        return factory.getOrCreateKotlinPackage(javaClass, "");
    }

    public static KDeclarationContainer getOrCreateKotlinPackage(Class javaClass, String moduleName) {
        return factory.getOrCreateKotlinPackage(javaClass, moduleName);
    }

    public static KClass getOrCreateKotlinClass(Class javaClass) {
        return factory.getOrCreateKotlinClass(javaClass);
    }

    public static KClass getOrCreateKotlinClass(Class javaClass, String internalName) {
        return factory.getOrCreateKotlinClass(javaClass, internalName);
    }

    public static KClass[] getOrCreateKotlinClasses(Class[] javaClasses) {
        int size = javaClasses.length;
        if (size == 0) {
            return EMPTY_K_CLASS_ARRAY;
        }
        KClass[] kClasses = new KClass[size];
        for (int i = 0; i < size; i++) {
            kClasses[i] = getOrCreateKotlinClass(javaClasses[i]);
        }
        return kClasses;
    }

    public static String renderLambdaToString(Lambda lambda) {
        return factory.renderLambdaToString(lambda);
    }

    public static String renderLambdaToString(FunctionBase lambda) {
        return factory.renderLambdaToString(lambda);
    }

    public static KFunction function(FunctionReference f) {
        return factory.function(f);
    }

    public static KProperty0 property0(PropertyReference0 p) {
        return factory.property0(p);
    }

    public static KMutableProperty0 mutableProperty0(MutablePropertyReference0 p) {
        return factory.mutableProperty0(p);
    }

    public static KProperty1 property1(PropertyReference1 p) {
        return factory.property1(p);
    }

    public static KMutableProperty1 mutableProperty1(MutablePropertyReference1 p) {
        return factory.mutableProperty1(p);
    }

    public static KProperty2 property2(PropertyReference2 p) {
        return factory.property2(p);
    }

    public static KMutableProperty2 mutableProperty2(MutablePropertyReference2 p) {
        return factory.mutableProperty2(p);
    }

    public static KType typeOf(KClassifier classifier) {
        return factory.typeOf(classifier, Collections.emptyList(), false);
    }

    public static KType typeOf(Class klass) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Collections.emptyList(), false);
    }

    public static KType typeOf(Class klass, KTypeProjection arg1) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Collections.singletonList(arg1), false);
    }

    public static KType typeOf(Class klass, KTypeProjection arg1, KTypeProjection arg2) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Arrays.asList(arg1, arg2), false);
    }

    public static KType typeOf(Class klass, KTypeProjection... arguments) {
        return factory.typeOf(getOrCreateKotlinClass(klass), ArraysKt.toList(arguments), false);
    }

    public static KType nullableTypeOf(KClassifier classifier) {
        return factory.typeOf(classifier, Collections.emptyList(), true);
    }

    public static KType nullableTypeOf(Class klass) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Collections.emptyList(), true);
    }

    public static KType nullableTypeOf(Class klass, KTypeProjection arg1) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Collections.singletonList(arg1), true);
    }

    public static KType nullableTypeOf(Class klass, KTypeProjection arg1, KTypeProjection arg2) {
        return factory.typeOf(getOrCreateKotlinClass(klass), Arrays.asList(arg1, arg2), true);
    }

    public static KType nullableTypeOf(Class klass, KTypeProjection... arguments) {
        return factory.typeOf(getOrCreateKotlinClass(klass), ArraysKt.toList(arguments), true);
    }

    public static KTypeParameter typeParameter(Object container, String name, KVariance variance, boolean isReified) {
        return factory.typeParameter(container, name, variance, isReified);
    }

    public static void setUpperBounds(KTypeParameter typeParameter, KType bound) {
        factory.setUpperBounds(typeParameter, Collections.singletonList(bound));
    }

    public static void setUpperBounds(KTypeParameter typeParameter, KType... bounds) {
        factory.setUpperBounds(typeParameter, ArraysKt.toList(bounds));
    }

    public static KType platformType(KType lowerBound, KType upperBound) {
        return factory.platformType(lowerBound, upperBound);
    }

    public static KType mutableCollectionType(KType type) {
        return factory.mutableCollectionType(type);
    }

    public static KType nothingType(KType type) {
        return factory.nothingType(type);
    }
}
