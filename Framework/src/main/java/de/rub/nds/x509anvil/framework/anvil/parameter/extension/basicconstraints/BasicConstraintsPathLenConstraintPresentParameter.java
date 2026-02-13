/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter.extension.basicconstraints;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.util.ArrayList;
import java.util.List;

public class BasicConstraintsPathLenConstraintPresentParameter
        extends BooleanCertificateSpecificParameter {

    public BasicConstraintsPathLenConstraintPresentParameter(ParameterScope parameterScope) {
        super(
                new ParameterIdentifier(
                        X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
                        parameterScope));
    }

    public BasicConstraintsPathLenConstraintPresentParameter(
            Boolean selectedValue, ParameterScope parameterScope) {
        super(
                selectedValue,
                new ParameterIdentifier(
                        X509AnvilParameterType.EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
                        parameterScope));
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new BasicConstraintsPathLenConstraintPresentParameter(
                selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    protected void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        BasicConstraintsConfig config =
                (BasicConstraintsConfig)
                        X509CertificateConfigUtil.getExtensionConfig(
                                certificateConfig, X509ExtensionType.BASIC_CONSTRAINTS);
        if (getSelectedValue()) {
            config.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
        } else {
            config.setIncludePathLenConstraint(DefaultEncodingRule.OMIT);
        }
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, Boolean>> parameterValues =
                new ArrayList<>();
        if (!getParameterScope().isEntity()) {
            parameterValues.add(generateValue(true));
        }
        parameterValues.add(generateValue(false));

        return parameterValues;
    }

    @Override
    protected boolean canBeDisabled(DerivationScope derivationScope) {
        return true;
    }
}
