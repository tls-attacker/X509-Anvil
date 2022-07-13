package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;

public class X509AnvilParameterFactory extends ParameterFactory {
    @Override
    public DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        return null;
    }

    @Override
    public ParameterScope resolveParameterScope(String s) {
        return ParameterScope.NO_SCOPE;
    }
}
