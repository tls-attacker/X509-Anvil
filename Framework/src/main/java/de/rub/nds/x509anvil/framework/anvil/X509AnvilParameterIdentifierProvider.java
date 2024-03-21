/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.DefaultModelTypes;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterIdentifierProvider;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;
import org.apache.commons.lang3.NotImplementedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class X509AnvilParameterIdentifierProvider extends ParameterIdentifierProvider {

    private static List<ParameterIdentifier> allParameterIdentifiers;

    private List<ParameterIdentifier>
        generateAllParameterIdentifiersWithDerivationScope(DerivationScope derivationScope) {
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());
        int intermediateCertsModeled =
            AnnotationUtil.resolveIntermediateCertsModeled(derivationScope.getExtensionContext());
        int numCertificateScopes = Integer.min(maxChainLength, 2 + intermediateCertsModeled);

        List<ParameterIdentifier> parameterIdentifiers = new ArrayList<>();
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));

        // Parameters for root certificate
        if (!AnnotationUtil.resolveStaticRoot(derivationScope.getExtensionContext())) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers.add(new ParameterIdentifier(x509AnvilParameterType, X509AnvilParameterScope.ROOT));
            }
        }

        // Parameters for intermediate certificates
        for (int i = 0; i < numCertificateScopes - 2; i++) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers.add(new ParameterIdentifier(x509AnvilParameterType,
                    X509AnvilParameterScope.createIntermediateScope(i)));
            }
        }

        // Parameters for entity certificate
        if (numCertificateScopes >= 2) {
            for (X509AnvilParameterType x509AnvilParameterType : getModeledParameterTypes()) {
                parameterIdentifiers
                    .add(new ParameterIdentifier(x509AnvilParameterType, X509AnvilParameterScope.ENTITY));
            }
        }

        return parameterIdentifiers;
    }

    public static List<X509AnvilParameterType> getModeledParameterTypes() {
        return Arrays.stream(X509AnvilParameterType.values()).filter(t -> t != X509AnvilParameterType.CHAIN_LENGTH)
            .filter(t -> !t.name().startsWith("EXT_KEY_USAGE")).filter(t -> !t.name().contains("UNIQUE"))
            .filter(t -> !t.name().contains("NC")).collect(Collectors.toList());

    }

    @Override
    public List<ParameterIdentifier> getModelParameterIdentifiers(DerivationScope derivationScope) {
        String modelType = derivationScope.getModelType();
        if (modelType.equals(DefaultModelTypes.ALL_PARAMETERS)) {
            return getAllParameterIdentifiers(derivationScope);
        }
        return Collections.emptyList();
    }

    public static List<ParameterIdentifier> getAllParameterIdentifiers(DerivationScope derivationScope) {
        if (allParameterIdentifiers == null) {
            allParameterIdentifiers =
                ((X509AnvilParameterIdentifierProvider) AnvilContext.getInstance().getParameterIdentifierProvider())
                    .generateAllParameterIdentifiersWithDerivationScope(derivationScope);
        }
        return allParameterIdentifiers;
    }

    @Override
    public List<ParameterIdentifier> generateAllParameterIdentifiers() {
        throw new NotImplementedException("Currently only implemented with DerivationScope provided.");
    }
}
