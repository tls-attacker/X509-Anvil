package de.rub.nds.x509anvil.framework.annotation;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;

public class AnnotationUtil {

    public static ChainLength resolveChainLengthAnnotation(ExtensionContext extensionContext) {
        Method testMethod = extensionContext.getRequiredTestMethod();
        return testMethod.getAnnotation(ChainLength.class);
    }

    public static int resolveMaxChainLength(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getContextDelegate().getTestConfig().getDefaultMaxChainLength();
        }
        return chainLengthAnnotation.maxLength();
    }

    public static int resolveMinChainLength(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getContextDelegate().getTestConfig().getDefaultMinChainLength();
        }
        return chainLengthAnnotation.minLength();
    }

    public static int resolveIntermediateCertsModeled(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            return ContextHelper.getContextDelegate().getTestConfig().getDefaultIntermediateCertsModeled();
        }
        return chainLengthAnnotation.intermediateCertsModeled();
    }

    public static int resolveMaxEntityCertChainPosition(ExtensionContext extensionContext) {
        int maxChainLength = resolveMaxChainLength(extensionContext);
        int intermediateCertsModeled = resolveIntermediateCertsModeled(extensionContext);
        return Integer.min(maxChainLength-1, intermediateCertsModeled + 1);
    }

    public static boolean resolveStaticRoot(ExtensionContext extensionContext) {
        Method testMethod = extensionContext.getRequiredTestMethod();
        StaticRoot staticRootAnnotation = testMethod.getAnnotation(StaticRoot.class);
        if (staticRootAnnotation == null) {
            return ContextHelper.getContextDelegate().getTestConfig().getUseStaticRootCertificate();
        }
        return staticRootAnnotation.value();
    }
}
