package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ConstraintHelper;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class HashAlgorithmParameter extends CertificateSpecificParameter<HashAlgorithm> {

    public HashAlgorithmParameter(ParameterScope parameterScope) {
        super (new ParameterIdentifier(X509AnvilParameterType.HASH_ALGORITHM, parameterScope), HashAlgorithm.class);
    }

    public HashAlgorithmParameter(ParameterScope parameterScope, HashAlgorithm value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, HashAlgorithm> generateValue(HashAlgorithm selectedValue) {
        return new HashAlgorithmParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        return Arrays.stream(HashAlgorithm.values()).map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {

    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        defaultConstraints.add(0, ValueRestrictionConstraintBuilder.init("MD2, MD4, MD5 cannot be used with DSA or ECDSA", derivationScope)
                .target(this)
                .requiredParameter(getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
                .restrictValues(Arrays.asList(HashAlgorithm.MD2, HashAlgorithm.MD4, HashAlgorithm.MD5))
                .condition((target, requiredParameters) -> {
                    KeyType keyType = (KeyType) ConstraintHelper.getParameterValue(requiredParameters, getScopedIdentifier(X509AnvilParameterType.KEY_TYPE)).getSelectedValue();
                    return keyType != KeyType.RSA;
                })
                .get()
        );

        return defaultConstraints;
    }
}
