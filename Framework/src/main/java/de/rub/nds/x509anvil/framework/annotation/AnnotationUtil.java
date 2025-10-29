/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.annotation;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import java.lang.reflect.Method;
import org.junit.jupiter.api.extension.ExtensionContext;

public class AnnotationUtil {

    public static ChainLength resolveChainLengthAnnotation(ExtensionContext extensionContext) {
        Method testMethod = extensionContext.getRequiredTestMethod();
        return testMethod.getAnnotation(ChainLength.class);
    }

    public static int resolveMaxChainLength(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getTestConfig().getDefaultMaxChainLength();
        }
        return chainLengthAnnotation.maxLength();
    }

    public static int resolveMinChainLength(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getTestConfig().getDefaultMinChainLength();
        }
        return chainLengthAnnotation.minLength();
    }

    public static int resolveIntermediateCertsModeled(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getTestConfig().getDefaultIntermediateCertsModeled();
        }
        return chainLengthAnnotation.intermediateCertsModeled();
    }

    public static int resolveMaxEntityCertChainPosition(ExtensionContext extensionContext) {
        int maxChainLength = resolveMaxChainLength(extensionContext);
        int intermediateCertsModeled = resolveIntermediateCertsModeled(extensionContext);
        return Integer.min(maxChainLength - 1, intermediateCertsModeled + 1);
    }

    public static boolean resolveStaticRoot(ExtensionContext extensionContext) {
        Method testMethod = extensionContext.getRequiredTestMethod();
        StaticRoot staticRootAnnotation = testMethod.getAnnotation(StaticRoot.class);
        if (staticRootAnnotation == null) {
            return true;
        }
        return staticRootAnnotation.value();
    }
}
