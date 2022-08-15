package de.rub.nds.x509anvil.framework.annotation;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.x509anvil.framework.constants.Severity;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface SeverityLevel {
    @JsonProperty("severity")
    Severity value();
}
