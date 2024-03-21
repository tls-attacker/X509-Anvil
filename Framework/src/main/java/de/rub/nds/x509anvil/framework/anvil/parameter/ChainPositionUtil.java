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
import de.rub.nds.x509anvil.framework.annotation.AnnotationUtil;

public class ChainPositionUtil {

    public static boolean isRoot(int chainPosition) {
        return chainPosition == 0;
    }

    public static boolean isEntity(int chainPosition, int chainLength, DerivationScope derivationScope) {
        int maxEntityCertChainPosition =
            AnnotationUtil.resolveMaxEntityCertChainPosition(derivationScope.getExtensionContext());
        return chainPosition == Integer.min(maxEntityCertChainPosition, chainLength - 1);
    }

    public static boolean isIntermediate(int chainPosition, int chainLength, DerivationScope derivationScope) {
        return !isRoot(chainPosition) && !isEntity(chainPosition, chainLength, derivationScope);
    }
}
