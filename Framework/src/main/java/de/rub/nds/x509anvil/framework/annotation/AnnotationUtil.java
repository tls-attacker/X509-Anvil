package de.rub.nds.x509anvil.framework.annotation;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
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
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultMaxChainLength();
        }
        return chainLengthAnnotation.maxLength();
    }

    public static int resolveMinChainLength(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultMinChainLength();
        }
        return chainLengthAnnotation.minLength();
    }

    public static int resolveIntermediateCertsModeled(ExtensionContext extensionContext) {
        ChainLength chainLengthAnnotation = resolveChainLengthAnnotation(extensionContext);
        if (chainLengthAnnotation == null) {
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultIntermediateCertsModeled();
        }
        return chainLengthAnnotation.intermediateCertsModeled();
    }

    public static int resolveMaxEntityCertChainPosition(ExtensionContext extensionContext) {
        int maxChainLength = resolveMaxChainLength(extensionContext);
        int intermediateCertsModeled = resolveIntermediateCertsModeled(extensionContext);
        return Integer.min(maxChainLength-1, intermediateCertsModeled + 1);
    }
}
