/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.annotation;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;

/**
 *
 */
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
            return ContextHelper.getTestConfig().getUseStaticRootCertificate();
        }
        return staticRootAnnotation.value();
    }
}
