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

    public static int resolveMaxLength(ChainLength chainLengthAnnotation) {
        if (chainLengthAnnotation == null) {
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultMaxChainLength();
        }
        return chainLengthAnnotation.maxLength();
    }

    public static int resolveMinLength(ChainLength chainLengthAnnotation) {
        if (chainLengthAnnotation == null) {
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultMinChainLength();
        }
        return chainLengthAnnotation.minLength();
    }

    public static int resolveIntermediateCertsModeled(ChainLength chainLengthAnnotation) {
        if (chainLengthAnnotation == null) {
            TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
            return testConfig.getDefaultIntermediateCertsModeled();
        }
        return chainLengthAnnotation.intermediateCertsModeled();
    }
}
