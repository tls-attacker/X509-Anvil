package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;

public class SubjectUniqueIdParameter extends UniqueIdParameter {

    public SubjectUniqueIdParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID, parameterScope),
                X509AnvilParameterType.SUBJECT_UNIQUE_ID_PRESENT);
    }

    public SubjectUniqueIdParameter(BitString selectedValue, ParameterScope parameterScope) {
        super(selectedValue,
                new ParameterIdentifier(X509AnvilParameterType.ISSUER_UNIQUE_ID, parameterScope),
                X509AnvilParameterType.SUBJECT_UNIQUE_ID_PRESENT);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, BitString> generateValue(BitString selectedValue) {
        return new SubjectUniqueIdParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToConfig(X509CertificateChainConfig config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            getCertificateConfigByScope(config).setSubjectUniqueId(getSelectedValue());
        }
    }
}
