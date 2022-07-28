package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class ExtensionsPresentParameter extends  BooleanCertificateSpecificParameter {
    // TODO If present, this field is a SEQUENCE of one or more certificate extensions.

    public ExtensionsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    public ExtensionsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.EXTENSIONS_PRESENT, parameterScope));
    }

    @Override
    public List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        // CA certificates must contain BasicConstraints extension
        if (!getParameterScope().isEntity()) {
            return Collections.singletonList(generateValue(true));
        }
        return super.getNonNullParameterValues(derivationScope);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new ExtensionsPresentParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setExtensionsPresent(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        defaultConstraints.add(ValueRestrictionConstraintBuilder.<Boolean>init("Extensions may only be present in v3 certificates", derivationScope)
                .target(this)
                .requiredParameter(getScopedIdentifier(X509AnvilParameterType.VERSION))
                .restrictValues(Collections.singletonList(true))
                .condition((target, requiredParameters) -> {
                    Integer version = ((VersionParameter) requiredParameters.get(0)).getSelectedValue();
                    return !Objects.equals(version, 2);
                })
                .get()
        );

        return defaultConstraints;
    }
}
