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
import de.rub.nds.anvilcore.junit.CombinatorialAnvilTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.model.config.ConfigContainer;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.registry.Registry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.security.Security;

@ExtendWith({
    // EndpointCondition.class,
    // TlsVersionCondition.class,
    // KexCondition.class,
    // MethodConditionExtension.class,
    // EnforcedSenderRestrictionConditionExtension.class,
    // ValueConstraintsConditionExtension.class,
    X509TestRunnerResolver.class })
public class X509AnvilTest extends CombinatorialAnvilTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected ParameterCombination parameterCombination;

    @BeforeAll
    public static void initialize() {
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();
        AnvilContext.getInstance().addParameterTypes(X509AnvilParameterType.values(), new X509AnvilParameterFactory());
        AnvilContext.getInstance().setModelBasedIpmFactory(new X509AnvilModelBasedIpmFactory());
        AnvilContext.getInstance().setApplicationSpecificContextDelegate(new X509AnvilContextDelegate(new TestConfig()));
        AnvilContext.getInstance().setTestStrength(2);
    }

    public X509CertificateChainConfig prepareConfig(ArgumentsAccessor argumentsAccessor,
        X509VerifierRunner testRunner) {
        X509CertificateChainConfig config = initializeConfig();
        parameterCombination =
            ParameterCombination.fromArgumentsAccessor(argumentsAccessor, new DerivationScope(extensionContext));
        parameterCombination.applyToConfig(ConfigContainer.fromConfig(X509CertificateChainConfig.class, config));
        testRunner.setPreparedConfig(config);
        testRunner.setParameterCombination(parameterCombination);
        return config;
    }

    public X509CertificateChainConfig initializeConfig() {
        return new X509CertificateChainConfig();
    }
}
