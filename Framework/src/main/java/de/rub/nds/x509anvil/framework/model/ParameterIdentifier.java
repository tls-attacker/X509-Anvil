/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model;

import java.util.Objects;

public class ParameterIdentifier {
    private final ParameterScope parameterScope;
    private final ParameterType parameterType;

    public ParameterIdentifier(ParameterScope parameterScope, ParameterType parameterType) {
        this.parameterScope = parameterScope;
        this.parameterType = parameterType;
    }

    public ParameterScope getParameterScope() {
        return parameterScope;
    }

    public ParameterType getParameterType() {
        return parameterType;
    }

    @Override
    public String toString() {
        return parameterScope.toString().toLowerCase() + "." + parameterType.toString().toLowerCase();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ParameterIdentifier)) {
            return false;
        }
        ParameterIdentifier other = (ParameterIdentifier) obj;
        return this.parameterScope == other.parameterScope && this.parameterType == other.parameterType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.parameterScope, this.parameterType);
    }
}
