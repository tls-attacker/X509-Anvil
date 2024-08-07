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
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.Extension;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

public class BasicConstraintsPathLenConstraintPresentParameter extends BooleanCertificateSpecificParameter {

    public BasicConstraintsPathLenConstraintPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
            parameterScope));
    }

    public BasicConstraintsPathLenConstraintPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(
            X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT, parameterScope));
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new BasicConstraintsPathLenConstraintPresentParameter(selectedValue,
            getParameterIdentifier().getParameterScope());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        // BasicConstraintsExtensionConfig extensionConfig =
        //     (BasicConstraintsExtensionConfig) certificateConfig.extension(ExtensionType.BASIC_CONSTRAINTS);
        // extensionConfig.setPathLenConstraintPresent(getSelectedValue());
        certificateConfig.addExtensions((Extension) null);
    }

    @Override
    public Map<ParameterIdentifier, Predicate<DerivationParameter>> getAdditionalEnableConditions() {
        Map<ParameterIdentifier, Predicate<DerivationParameter>> conditions = new HashMap<>();
        // Only model if ca is asserted
        conditions.put(getScopedIdentifier(X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_CA),
            CommonConstraints::enabledByParameterCondition);
        return conditions;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
