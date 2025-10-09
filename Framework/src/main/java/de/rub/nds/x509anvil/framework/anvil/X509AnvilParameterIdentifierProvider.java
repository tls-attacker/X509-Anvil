/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import static de.rub.nds.x509anvil.framework.constants.ChainValues.MAX_CHAIN_LENGTH;
import static de.rub.nds.x509anvil.framework.constants.ChainValues.MAX_INTERMEDIATE_CERTS_MODELED;

import de.rub.nds.anvilcore.context.AnvilContextRegistry;
import de.rub.nds.anvilcore.model.DefaultModelTypes;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterIdentifierProvider;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class X509AnvilParameterIdentifierProvider extends ParameterIdentifierProvider {

    private static List<ParameterIdentifier> allParameterIdentifiers;

    private List<ParameterIdentifier> generateAllParameterIdentifiersWithDerivationScope(
            DerivationScope derivationScope) {
        return generateAllParameterIdentifiersBase(
                AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext()),
                AnnotationUtil.resolveIntermediateCertsModeled(
                        derivationScope.getExtensionContext()),
                AnnotationUtil.resolveStaticRoot(derivationScope.getExtensionContext()));
    }

    private List<ParameterIdentifier> generateAllParameterIdentifiersWithoutDerivationScope() {
        return generateAllParameterIdentifiersBase(
                MAX_CHAIN_LENGTH.getValue(), MAX_INTERMEDIATE_CERTS_MODELED.getValue(), false);
    }

    private List<ParameterIdentifier> generateAllParameterIdentifiersBase(
            int maxChainLength, int intermediateCertsModeled, boolean staticRoot) {
        int numCertificateScopes = Integer.min(maxChainLength, 2 + intermediateCertsModeled);

        List<ParameterIdentifier> parameterIdentifiers = new ArrayList<>();
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));

        // Parameters for root certificate
        if (!staticRoot) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers.add(
                        new ParameterIdentifier(
                                x509AnvilParameterType, X509AnvilParameterScope.ROOT));
            }
        }

        // Parameters for intermediate certificates
        for (int i = 0; i < numCertificateScopes - 2; i++) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers.add(
                        new ParameterIdentifier(
                                x509AnvilParameterType,
                                X509AnvilParameterScope.createIntermediateScope(i)));
            }
        }

        // Parameters for entity certificate
        if (numCertificateScopes >= 2) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers.add(
                        new ParameterIdentifier(
                                x509AnvilParameterType, X509AnvilParameterScope.ENTITY));
            }
        }

        return parameterIdentifiers;
    }

    public static List<X509AnvilParameterType> getModeledParameterTypes() {
        return Arrays.stream(X509AnvilParameterType.values())
                .filter(t -> t != X509AnvilParameterType.CHAIN_LENGTH)
                .collect(Collectors.toList());
    }

    @Override
    public List<ParameterIdentifier> generateAllParameterIdentifiers(String anvilContextId) {
        if (allParameterIdentifiers == null) {
            allParameterIdentifiers =
                    ((X509AnvilParameterIdentifierProvider)
                                    AnvilContextRegistry.getContext(anvilContextId).getParameterIdentifierProvider())
                            .generateAllParameterIdentifiersWithoutDerivationScope();
        }
        return allParameterIdentifiers;
    }

    @Override
    public List<ParameterIdentifier> getModelParameterIdentifiers(DerivationScope derivationScope) {
        String modelType = derivationScope.getModelType();
        if (modelType.equals(DefaultModelTypes.ALL_PARAMETERS)) {
            return generateAllParameterIdentifiersWithDerivationScope(derivationScope);
        }
        return Collections.emptyList();
    }
}
