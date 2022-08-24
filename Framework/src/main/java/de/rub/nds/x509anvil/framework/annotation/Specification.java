package de.rub.nds.x509anvil.framework.annotation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface Specification {
    @JsonProperty("document")
    String document();

    @JsonProperty("section")
    String section() default "";

    @JsonProperty("text")
    String text() default "";
}