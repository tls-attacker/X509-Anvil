/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExtensionsPresentParameter extends BooleanCertificateSpecificParameter {

    public ExtensionsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    public ExtensionsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(
                selectedValue,
                new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, Boolean>> getNonNullParameterValues(
            DerivationScope derivationScope) {
        // CA certificates must contain BasicConstraints extension
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(
            Boolean selectedValue) {
        return new ExtensionsPresentParameter(
                selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setIncludeExtensions(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(
            DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints =
                super.getDefaultConditionalConstraints(derivationScope);

        defaultConstraints.add(getCipherSuiteConstraint());

        return defaultConstraints;
    }

    private ConditionalConstraint getCipherSuiteConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(X509AnvilParameterType.VERSION));
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                X509AnvilParameterType.VERSION.name())
                        .by(
                                (ExtensionsPresentParameter extensionsPresentParameter,
                                 VersionParameter versionParameter) -> {
                                    boolean extensionsPresent = extensionsPresentParameter.getSelectedValue();
                                    int version = versionParameter.getSelectedValue();

                                    if (version == 0 || version == 1) {
                                        return !extensionsPresent;
                                    } else {
                                        return true;
                                    }
                                }));
    }
}
