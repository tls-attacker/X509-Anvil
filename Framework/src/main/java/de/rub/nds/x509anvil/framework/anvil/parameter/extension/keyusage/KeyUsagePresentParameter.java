package de.rub.nds.x509anvil.framework.anvil.parameter.extension.keyusage;

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

public class KeyUsagePresentParameter extends ExtensionPresentParameter {

    public KeyUsagePresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_KEY_USAGE_PRESENT, parameterScope), ExtensionType.KEY_USAGE);
    }

    public KeyUsagePresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXT_KEY_USAGE_PRESENT, parameterScope), ExtensionType.KEY_USAGE);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new KeyUsagePresentParameter(selectedValue, getParameterScope());
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}