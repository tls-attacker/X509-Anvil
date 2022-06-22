package de.rub.nds.x509anvil.framework.junit.test;

import de.rub.nds.x509anvil.framework.TestContext;
import de.rub.nds.x509anvil.framework.junit.execution.X509TestRunner;
import de.rub.nds.x509anvil.framework.junit.extension.ExtensionContextParameterResolver;
import de.rub.nds.x509anvil.framework.junit.extension.X509TestRunnerResolver;
import de.rub.nds.x509anvil.framework.model.DerivationScope;
import de.rub.nds.x509anvil.framework.model.ParameterCombination;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


@ExtendWith({
        //TestWatcher.class,
        //EndpointCondition.class,
        //TlsVersionCondition.class,
        //KexCondition.class,
        //MethodConditionExtension.class,
        //EnforcedSenderRestrictionConditionExtension.class,
        //ValueConstraintsConditionExtension.class,
        ExtensionContextParameterResolver.class,
        X509TestRunnerResolver.class
})
public abstract class X509VerifierTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected TestContext testContext;
    protected ExtensionContext extensionContext;
    protected ParameterCombination parameterCombination;

    public X509VerifierTest() {
        testContext = TestContext.getInstance();
    }

    @BeforeEach
    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public X509CertificateChainConfig prepareConfig(ArgumentsAccessor argumentsAccessor, X509TestRunner testRunner) {
        X509CertificateChainConfig config = initConfig();
        parameterCombination = ParameterCombination.fromArgumentsAccessor(argumentsAccessor, new DerivationScope(extensionContext));
        parameterCombination.applyToConfig(config, testContext);
        testRunner.setPreparedConfig(config);
        testRunner.setParameterCombination(parameterCombination);
        return config;
    }

    public TestContext getTestContext() {
        return testContext;
    }


    public abstract X509CertificateChainConfig initConfig();
}
