package androidx.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Host-test stand-in for the androidx annotation of the same name, so the engine
 * facade compiles on a desktop JVM without pulling in the Android support
 * libraries. Never shipped.
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD,
         ElementType.LOCAL_VARIABLE, ElementType.TYPE_USE})
public @interface NonNull {}
