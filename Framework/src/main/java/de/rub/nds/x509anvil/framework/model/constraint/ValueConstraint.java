/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.constraint;

import de.rub.nds.x509anvil.framework.model.ParameterIdentifier;

public class ValueConstraint {
    private final ParameterIdentifier affectedParameter;
    private final String evaluationMethod;
    private final Class<?> clazz;
    private final boolean dynamic;

    public ValueConstraint(ParameterIdentifier affectedParameter, String evaluationMethod, Class<?> clazz,
        boolean dynamic) {
        this.affectedParameter = affectedParameter;
        this.evaluationMethod = evaluationMethod;
        this.clazz = clazz;
        this.dynamic = dynamic;
    }

    public ParameterIdentifier getAffectedParameter() {
        return affectedParameter;
    }

    public String getEvaluationMethod() {
        return evaluationMethod;
    }

    public Class<?> getClazz() {
        return clazz;
    }

    public boolean isDynamic() {
        return dynamic;
    }
}
