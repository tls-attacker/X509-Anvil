package de.rub.nds.x509anvil.framework.junit.test;

import de.rub.nds.anvilcore.junit.ExtensionContextParameterResolver;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.model.config.ConfigContainer;
import de.rub.nds.x509anvil.framework.junit.execution.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.junit.extension.X509TestRunnerResolver;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.registry.Registry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.security.Security;


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

    static {
        // We need to call this statically, otherwise we would not be able to generate certificates from unit tests
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();
    }

    protected ExtensionContext extensionContext;
    protected ParameterCombination parameterCombination;

    @BeforeEach
    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public X509CertificateChainConfig prepareConfig(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) {
        X509CertificateChainConfig config = initConfig();
        parameterCombination = ParameterCombination.fromArgumentsAccessor(argumentsAccessor, new DerivationScope(extensionContext));
        parameterCombination.applyToConfig(ConfigContainer.fromConfig(X509CertificateChainConfig.class, config));
        testRunner.setPreparedConfig(config);
        testRunner.setParameterCombination(parameterCombination);
        return config;
    }

    public abstract X509CertificateChainConfig initConfig();
}
