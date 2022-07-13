package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;


public class X509AnvilParameterScope extends ParameterScope {
    // TODO Implement more dynamic scope behavior
    de.rub.nds.x509anvil.framework.model.ParameterScope parameterScope;

    public X509AnvilParameterScope(de.rub.nds.x509anvil.framework.model.ParameterScope parameterScope) {
        this.parameterScope = parameterScope;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return parameterScope.name().toLowerCase();
    }
}
