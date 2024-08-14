/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.CommonConstraints;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class BasicConstraintsCaParameter extends BooleanCertificateSpecificParameter {

    public BasicConstraintsCaParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CA, parameterScope));
    }

    public BasicConstraintsCaParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CA, parameterScope));
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        // Ca must be set for intermediate certificates
        if (getParameterScope().isIntermediate()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsCaParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        BasicConstraintsConfig config = (BasicConstraintsConfig) X509CertificateConfigUtil
            .getExtensionConfig(certificateConfig, X509ExtensionType.BASIC_CONSTRAINTS);
        config.setCa(getSelectedValue());
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        // Only model if corresponding ExtensionPresent parameter is true
        return Collections.singletonMap(getScopedIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PRESENT),
            CommonConstraints::enabledByParameterCondition);
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
