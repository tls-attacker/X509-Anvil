/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class CommonConstraints {
    public static <T> FlexibleConditionalConstraint valuesOnlyAllowedInV3Certs(DerivationScope derivationScope,
        CertificateSpecificParameter target, List<T> values) {
        return valuesNotAllowedForVersions(Arrays.asList(0, 1), derivationScope, target, values);
    }

    public static <T> FlexibleConditionalConstraint valuesNotAllowedForVersions(List<Integer> restrictedVersions,
        DerivationScope derivationScope, CertificateSpecificParameter target, List<T> values) {
        return ValueRestrictionConstraintBuilder
            .<T>init("Extensions may only be present in v3 certificates", derivationScope).target(target)
            .requiredParameter(target.getScopedIdentifier(X509AnvilParameterType.VERSION)).restrictValues(values)
            .condition((unused, requiredParameters) -> {
                Integer version = ((VersionParameter) requiredParameters.get(0)).getSelectedValue();
                for (int restrictedVersion : restrictedVersions) {
                    if (Objects.equals(version, restrictedVersion)) {
                        return true;
                    }
                }
                return false;
            }).get();
    }

    public static boolean enabledByParameterCondition(DerivationParameter enabler) {
        if (!enabler.getValueClass().equals(Boolean.class)) {
            throw new IllegalArgumentException("enabledByParameterCondition expects a Boolean value type");
        }
        if (enabler.getSelectedValue() == null) {
            return false;
        }
        return (Boolean) enabler.getSelectedValue();
    }
}
