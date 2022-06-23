package de.rub.nds.x509anvil.framework.junit.testchooser;

import de.rub.nds.x509anvil.framework.junit.context.TestContext;
import de.rub.nds.x509anvil.framework.annotations.TestChooser;
import de.rub.nds.x509anvil.framework.coffee4j.junit.CombinatorialX509VerifierTestExtension;
import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterModelFactory;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;
import org.junit.platform.commons.util.AnnotationUtils;

import java.lang.reflect.Method;
import java.util.stream.Stream;

public class TestChooserExtension implements TestTemplateInvocationContextProvider {
    @Override
    public boolean supportsTestTemplate(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return false;
        }

        Method testMethod = extensionContext.getRequiredTestMethod();
        if (!AnnotationUtils.isAnnotated(testMethod, TestChooser.class)) {
            return false;
        }

        DerivationScope derivationScope = new DerivationScope(extensionContext);
        if (ParameterModelFactory.mustUseSimpleModel(TestContext.getInstance(), derivationScope)) {
            // return new SimpleTestExtension().supportsTestTemplate(extensionContext);
            return false;
        } else {
            return new CombinatorialX509VerifierTestExtension().supportsTestTemplate(extensionContext);
        }
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(ExtensionContext extensionContext) {
        DerivationScope derivationScope = new DerivationScope(extensionContext);
        if (ParameterModelFactory.mustUseSimpleModel(TestContext.getInstance(), derivationScope)) {
            // TODO
            return null;
        } else {
            return new CombinatorialX509VerifierTestExtension().provideTestTemplateInvocationContexts(extensionContext);
        }
    }
}
