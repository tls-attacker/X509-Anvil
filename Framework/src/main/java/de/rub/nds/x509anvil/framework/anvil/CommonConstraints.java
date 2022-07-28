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
    public static <T> FlexibleConditionalConstraint valuesOnlyAllowedInV3Certs(DerivationScope derivationScope, CertificateSpecificParameter target, List<T> values) {
        return ValueRestrictionConstraintBuilder.<T>init("Extensions may only be present in v3 certificates", derivationScope)
                .target(target)
                .requiredParameter(target.getScopedIdentifier(X509AnvilParameterType.VERSION))
                .restrictValues(values)
                .condition((unused, requiredParameters) -> {
                    Integer version = ((VersionParameter) requiredParameters.get(0)).getSelectedValue();
                    return !Objects.equals(version, 2);
                })
                .get();
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
