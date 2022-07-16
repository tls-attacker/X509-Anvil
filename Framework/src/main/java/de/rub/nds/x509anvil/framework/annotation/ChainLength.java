package de.rub.nds.x509anvil.framework.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface ChainLength {
    int maxLength() default 3;
    int minLength() default 1;
    int intermediateCertsModeled() default 1;
}
