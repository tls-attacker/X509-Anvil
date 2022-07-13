/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rwth.swc.coffee4j.model.constraints.Constraint;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public abstract class CertificateSpecificParameter<T> extends X509AnvilDerivationParameter<T> {

    public CertificateSpecificParameter(ParameterIdentifier parameterIdentifier, Class<T> valueClass) {
        super(valueClass, parameterIdentifier);
    }

    /**
     * Creates a conditional constraint that enforces the parameter value to be null if and only if the certificate that
     * the parameter is associated with is not modelled. For example, if the parameter is associated with an
     * intermediate certificate and the certificate length parameter is 2, we don't need the parameter to be included.
     */
    private ConditionalConstraint createCertificateNotModeledConstraint() {
        Set<ParameterIdentifier> requiredParameters =
            Collections.singleton(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH, X509AnvilParameterScope.GLOBAL));
        Constraint constraint = ConstraintBuilder
            .constrain(getParameterIdentifier().toString(), requiredParameters.stream().findFirst().get().toString())
            .by((CertificateSpecificParameter<T> certificateSpecificParam, ChainLengthParameter chainLengthParam) -> {
                Integer chainLength = chainLengthParam.getSelectedValue();
                T selectedValue = certificateSpecificParam.getSelectedValue();
                return (certificateParameterScopeModeled(getParameterIdentifier().getParameterScope(), chainLength)
                    ^ selectedValue == null);
            });
        return new ConditionalConstraint(requiredParameters, constraint);
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);
        defaultConstraints.add(createCertificateNotModeledConstraint());
        return defaultConstraints;
    }

    private static boolean certificateParameterScopeModeled(ParameterScope parameterScope, int chainLength) {
        switch (parameterScope.getUniqueScopeIdentifier()) {
            case "cert_entity":
                return chainLength >= 1;
            case "cert_root":
                return chainLength >= 2;
            case "cert_intermediate":
                return chainLength >= 3;
            default:
                return false; // Not a certificate parameter scope
        }
    }

    protected X509CertificateConfig getCertificateConfigByScope(X509CertificateChainConfig certificateChainConfig) {
        switch (getParameterIdentifier().getParameterScope().getUniqueScopeIdentifier()) {
            case "cert_entity":
                return certificateChainConfig.getEntityCertificateConfig();
            case "cert_intermediate":
                return certificateChainConfig.getIntermediateCertificatesConfig();
            case "cert_root":
                return certificateChainConfig.getRootCertificateConfig();
            default:
                throw new UnsupportedOperationException("Invalid ParameterScope");
        }
    }
}
