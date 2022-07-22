package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;

public class IssuerUniqueIdParameter extends UniqueIdParameter {

    public IssuerUniqueIdParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.SUBJECT_UNIQUE_ID, parameterScope),
                X509AnvilParameterType.ISSUER_UNIQUE_ID_PRESENT);
    }

    public IssuerUniqueIdParameter(BitString selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.SUBJECT_UNIQUE_ID, parameterScope),
                X509AnvilParameterType.ISSUER_UNIQUE_ID_PRESENT);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, BitString> generateValue(BitString selectedValue) {
        return new IssuerUniqueIdParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setIssuerUniqueId(getSelectedValue());
    }
}