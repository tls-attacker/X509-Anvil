package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;


public class X509AnvilParameterScope extends ParameterScope {
    // TODO Implement more dynamic scope behavior
    ParameterScopeEnum parameterScope;

    public X509AnvilParameterScope(ParameterScopeEnum parameterScope) {
        this.parameterScope = parameterScope;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return parameterScope.name().toLowerCase();
    }

    public static X509AnvilParameterScope GLOBAL = new X509AnvilParameterScope(ParameterScopeEnum.GLOBAL);
    public static X509AnvilParameterScope CERT_ROOT = new X509AnvilParameterScope(ParameterScopeEnum.CERT_ROOT);
    public static X509AnvilParameterScope CERT_INTERMEDIATE = new X509AnvilParameterScope(ParameterScopeEnum.CERT_INTERMEDIATE);
    public static X509AnvilParameterScope CERT_ENTITY = new X509AnvilParameterScope(ParameterScopeEnum.CERT_ENTITY);
}
