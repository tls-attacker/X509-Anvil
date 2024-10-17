/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;

public class SubjectUniqueIdParameter extends UniqueIdParameter {

    public SubjectUniqueIdParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.SUBJECT_UNIQUE_ID, parameterScope),
            X509AnvilParameterType.SUBJECT_UNIQUE_ID_PRESENT);
    }

    public SubjectUniqueIdParameter(byte[] selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.SUBJECT_UNIQUE_ID, parameterScope),
            X509AnvilParameterType.SUBJECT_UNIQUE_ID_PRESENT);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, byte[]> generateValue(byte[] selectedValue) {
        return new SubjectUniqueIdParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setSubjectUniqueId(getSelectedValue());
    }
}
