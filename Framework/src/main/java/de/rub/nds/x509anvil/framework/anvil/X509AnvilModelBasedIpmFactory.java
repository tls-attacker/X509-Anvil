/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ModelBasedIpmFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class X509AnvilModelBasedIpmFactory extends ModelBasedIpmFactory {
    @Override
    protected List<ParameterIdentifier> getAllParameterIdentifiers(DerivationScope derivationScope) {
        int maxChainLength = AnnotationUtil.resolveMaxChainLength(derivationScope.getExtensionContext());
        int intermediateCertsModeled = AnnotationUtil.resolveIntermediateCertsModeled(derivationScope.getExtensionContext());
        int numCertificateScopes = Integer.min(maxChainLength, 2 + intermediateCertsModeled);

        List<ParameterIdentifier> parameterIdentifiers = new ArrayList<>();
        parameterIdentifiers.add(new ParameterIdentifier(X509AnvilParameterType.CHAIN_LENGTH));

        // certificate specific parameters
        TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
        int chainPosition = 0;
        // Forgo modeling root certificate if static root is used
        if (testConfig.getUseStaticRootCertificate()) {
            chainPosition = 1;
        }

        // Parameters for root certificate
        if (!testConfig.getUseStaticRootCertificate()) {
            for (X509AnvilParameterType x509AnvilParameterType : getModelledParameterTypes()) {
                parameterIdentifiers.add(new ParameterIdentifier(x509AnvilParameterType, X509AnvilParameterScope.ROOT));
            }
        }

        // Parameters for intermediate certificates
        for (int i = 0; i < numCertificateScopes - 2; i++) {
            for (X509AnvilParameterType x509AnvilParameterType : getModelledParameterTypes()) {
                parameterIdentifiers.add(new ParameterIdentifier(x509AnvilParameterType, X509AnvilParameterScope.createIntermediateScope(i)));
            }
        }

        // Parameters for entity certificate
        if (numCertificateScopes >= 2) {
            for (X509AnvilParameterType x509AnvilParameterType : getModelledParameterTypes()) {
                parameterIdentifiers.add(new ParameterIdentifier(x509AnvilParameterType, X509AnvilParameterScope.ENTITY));
            }
        }

        return parameterIdentifiers;
    }

    public static List<X509AnvilParameterType> getModelledParameterTypes() {
        return Arrays.asList(
                X509AnvilParameterType.VERSION,
                X509AnvilParameterType.EXTENSIONS_PRESENT,
                X509AnvilParameterType.EXT_KEY_USAGE_PRESENT
        );
    }
}
