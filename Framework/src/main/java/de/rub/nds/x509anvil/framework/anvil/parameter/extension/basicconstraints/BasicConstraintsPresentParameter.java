package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.extension.ExtensionPresentParameter;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

import java.util.Collections;
import java.util.List;

public class BasicConstraintsPresentParameter extends ExtensionPresentParameter {
    public BasicConstraintsPresentParameter(ParameterScope parameterScope, ExtensionType extensionType) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT, parameterScope), extensionType);
    }

    public BasicConstraintsPresentParameter(Boolean selectedValue, ParameterScope parameterScope, ExtensionType extensionType) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT, parameterScope), extensionType);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsPresentParameter(selectedValue, getParameterScope(), getExtensionType());
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        // BasicConstraints must be present for intermediate certificates
        if (getParameterScope().isIntermediate()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
