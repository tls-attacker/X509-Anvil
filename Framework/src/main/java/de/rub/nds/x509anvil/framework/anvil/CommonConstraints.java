/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.FlexibleConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.CertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.anvil.parameter.VersionParameter;

import java.util.List;
import java.util.Objects;

public class CommonConstraints {
    public static <T> FlexibleConditionalConstraint valuesNotAllowedForVersions(
            List<Integer> restrictedVersions,
            DerivationScope derivationScope,
            CertificateSpecificParameter target,
            List<T> values) {
        return ValueRestrictionConstraintBuilder.<T>init(
                        "Version Restriction", derivationScope)
                .target(target)
                .requiredParameter(target.getScopedIdentifier(X509AnvilParameterType.VERSION))
                .restrictValues(values)
                .condition(
                        (unused, requiredParameters) -> {
                            Integer version =
                                    ((VersionParameter) requiredParameters.getLast())
                                            .getSelectedValue();
                            for (int restrictedVersion : restrictedVersions) {
                                if (Objects.equals(version, restrictedVersion)) {
                                    return true;
                                }
                            }
                            return false;
                        })
                .get();
    }

    public static boolean enabledByParameterCondition(DerivationParameter enabler) {
        if (!enabler.getValueClass().equals(Boolean.class)) {
            throw new IllegalArgumentException(
                    "enabledByParameterCondition expects a Boolean value type");
        }
        if (enabler.getSelectedValue() == null) {
            return false;
        }
        return (Boolean) enabler.getSelectedValue();
    }
}
