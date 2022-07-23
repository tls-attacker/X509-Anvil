package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ConstraintHelper;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Arrays;
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
        // TODO Feature extraction for hash algorithms
        return Arrays
                .stream(HashAlgorithm.values())
                .filter(h -> h != HashAlgorithm.SHA1)
                .filter(h -> h != HashAlgorithm.MD2)
                .filter(h -> h != HashAlgorithm.MD4)
                .filter(h -> h != HashAlgorithm.MD5)
                .filter(h -> h != HashAlgorithm.NONE)
                .map(this::generateValue)
                .collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setHashAlgorithm(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);


        defaultConstraints.add(0, ValueRestrictionConstraintBuilder.init("DSA does not work with SHA512 or SHA384", derivationScope)
                .target(this)
                .requiredParameter(getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
                .restrictValues(Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384))
                .condition((target, requiredParameters) -> {
                    KeyType keyType = (KeyType) ConstraintHelper.getParameterValue(requiredParameters, getScopedIdentifier(X509AnvilParameterType.KEY_TYPE)).getSelectedValue();
                    return keyType == KeyType.DSA;
                })
                .get()
        );



        return defaultConstraints;
    }
}
