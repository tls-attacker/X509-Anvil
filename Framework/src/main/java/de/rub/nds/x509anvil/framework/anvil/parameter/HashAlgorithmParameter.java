/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.constraint.ConstraintHelper;
import de.rub.nds.anvilcore.model.constraint.ValueRestrictionConstraintBuilder;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.constants.KeyTypeLengthPair;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class HashAlgorithmParameter extends CertificateSpecificParameter<HashAlgorithm> {

    public HashAlgorithmParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.HASH_ALGORITHM, parameterScope), HashAlgorithm.class);
    }

    public HashAlgorithmParameter(ParameterScope parameterScope, HashAlgorithm value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, HashAlgorithm>
        generateValue(HashAlgorithm selectedValue) {
        return new HashAlgorithmParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        if (getParameterScope().isEntity()) {
            return featureReport.getSupportedEntityHashAlgorithms().stream().map(this::generateValue)
                .collect(Collectors.toList());
        }
        return featureReport.getSupportedHashAlgorithms().stream().map(this::generateValue)
            .collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setHashAlgorithm(getSelectedValue());
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope derivationScope) {
        List<ConditionalConstraint> defaultConstraints = super.getDefaultConditionalConstraints(derivationScope);

        // We need to build constraints for any unsupported keytype-hashalgo combinations
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        List<KeyType> supportedKeyTypes;
        List<HashAlgorithm> supportedHashAlgorithms;
        if (getParameterScope().isEntity()) {
            supportedKeyTypes = featureReport.getSupportedEntityKeyTypes();
            supportedHashAlgorithms = featureReport.getSupportedEntityHashAlgorithms();
        } else {
            supportedKeyTypes = featureReport.getSupportedKeyTypes();
            supportedHashAlgorithms = featureReport.getSupportedHashAlgorithms();
        }

        for (KeyType keyType : supportedKeyTypes) {
            for (HashAlgorithm hashAlgorithm : supportedHashAlgorithms) {
                try {
                    SignatureAlgorithm resultingSignatureAlgorithm =
                        SignatureAlgorithm.fromKeyHashCombination(keyType, hashAlgorithm);
                    if (getParameterScope().isEntity()
                        && !featureReport.entityAlgorithmSupported(resultingSignatureAlgorithm)
                        || !getParameterScope().isEntity()
                            && !featureReport.algorithmSupported(resultingSignatureAlgorithm)) {
                        defaultConstraints
                            .add(createSignatureAlgorithmExclusionConstraint(keyType, hashAlgorithm, derivationScope));
                    }
                } catch (IllegalArgumentException e) {
                    // Signature algorithm does not exist (i.e. not supported by X509-Anvil)
                    defaultConstraints
                        .add(createSignatureAlgorithmExclusionConstraint(keyType, hashAlgorithm, derivationScope));
                }
            }
        }

        defaultConstraints.add(
            ValueRestrictionConstraintBuilder.init("DSA and RSA512 do not work with SHA512 or SHA384", derivationScope)
                .target(this).requiredParameter(getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
                .restrictValues(Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384))
                .condition((target, requiredParameters) -> {
                    KeyTypeLengthPair keyTypeLengthPair = (KeyTypeLengthPair) ConstraintHelper
                        .getParameterValue(requiredParameters, getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
                        .getSelectedValue();
                    if (keyTypeLengthPair == null) {
                        return false;
                    }
                    return (keyTypeLengthPair.getKeyType() == KeyType.DSA
                        || keyTypeLengthPair.getKeyType() == KeyType.RSA) && keyTypeLengthPair.getKeyLength() < 1024;
                }).get());

        return defaultConstraints;
    }

    public ConditionalConstraint createSignatureAlgorithmExclusionConstraint(KeyType keyType,
        HashAlgorithm hashAlgorithm, DerivationScope derivationScope) {
        return ValueRestrictionConstraintBuilder
            .init("Target does not support " + keyType.name() + " with " + hashAlgorithm.name(), derivationScope)
            .target(this).requiredParameter(getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
            .restrictValues(Collections.singletonList(hashAlgorithm)).condition((target, requiredParameters) -> {
                KeyTypeLengthPair selectedKeyTypeLengthPair = (KeyTypeLengthPair) ConstraintHelper
                    .getParameterValue(requiredParameters, getScopedIdentifier(X509AnvilParameterType.KEY_TYPE))
                    .getSelectedValue();
                return selectedKeyTypeLengthPair != null && selectedKeyTypeLengthPair.getKeyType() == keyType;
            }).get();
    }
}
