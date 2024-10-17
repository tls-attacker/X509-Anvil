/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.junit.AnvilTestBaseClass;
import de.rub.nds.anvilcore.junit.extension.MethodConditionExtension;
import de.rub.nds.anvilcore.junit.extension.ValueConstraintsConditionExtension;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ParameterCombination;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.x509anvil.framework.featureextraction.UnsupportedFeatureException;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeException;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

@ExtendWith({ MethodConditionExtension.class, ValueConstraintsConditionExtension.class, X509TestRunnerResolver.class })
public class X509AnvilTest extends AnvilTestBaseClass {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected ParameterCombination parameterCombination;

    @BeforeAll
    public static void initialize() throws UnsupportedFeatureException, ProbeException {
        ContextHelper.initializeContext();
    }

    @Deprecated
    public X509CertificateChainConfig prepareConfig(ArgumentsAccessor argumentsAccessor,
        X509VerifierRunner testRunner) {
        X509CertificateChainConfig config = initializeConfig();
        parameterCombination = ParameterCombination.fromArgumentsAccessor(argumentsAccessor,
            DerivationScope.fromExtensionContext(extensionContext));
        parameterCombination.applyToConfig(config);
        testRunner.setPreparedConfig(config);
        testRunner.setParameterCombination(parameterCombination);
        return config;
    }

    public X509CertificateChainConfig prepareConfig(X509VerifierRunner testRunner) {
        X509CertificateChainConfig config = initializeConfig();
        AnvilTestCase testCase = AnvilTestCase.fromExtensionContext(extensionContext);
        parameterCombination = new ParameterCombination(testCase.getParameterCombination().getParameterValues(),
            testCase.getParameterCombination().getDerivationScope());
        parameterCombination.applyToConfig(config);
        testRunner.setPreparedConfig(config);
        testRunner.setParameterCombination(parameterCombination);
        return config;
    }

    /**
     * Tests whether the given certificate modification leads to the certificate being correctly rejected or accepted.
     * Modifications apply to prepared certificates.
     */
    private void assertBoolean(X509VerifierRunner testRunner, boolean expectValid,
        boolean entity, X509CertificateModifier modifier) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator =
            new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();

        X509Certificate certificate;
        if (entity) {
            certificate = generatedCertificates.get(generatedCertificates.size() - 1);
        } else {
            certificate = generatedCertificates.get(generatedCertificates.size() - 2);
        }

        modifier.apply(certificate);
        VerifierResult result = testRunner.execute(generatedCertificates);
        // assert values are equal
        assert expectValid == result.isValid();
    }

    /**
     * Tests whether the given certificate modification leads to the certificate being correctly rejected or accepted.
     * Modifications apply to Configurations.
     */
    private void assertBoolean(X509VerifierRunner testRunner, boolean expectValid,
                               boolean entity, X509CertificateConfigModifier modifier)
            throws VerifierException, CertificateGeneratorException {
        // generate chain config
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateConfig config;
        // choose correct certificate config
        if (entity) {
            config = certificateChainConfig.getEntityCertificateConfig();
        } else {
            config = certificateChainConfig.getLastSigningConfig();
        }
        // apply modifications
        modifier.apply(config);
        VerifierResult result = testRunner.execute(certificateChainConfig);
        // assert values are equal
        assert expectValid == result.isValid();
    }

    private void assertBoolean(X509VerifierRunner testRunner, boolean expectValid,
        boolean entity, X509CertificateConfigModifier configModifier, X509CertificateModifier certificateModifier)
        throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateConfig config;
        // choose correct certificate config
        if (entity) {
            config = certificateChainConfig.getEntityCertificateConfig();
        } else {
            config = certificateChainConfig.getLastSigningConfig();
        }
        // apply modifications to config
        configModifier.apply(config);

        X509CertificateChainGenerator certificateChainGenerator =
            new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();

        X509Certificate certificate;
        if (entity) {
            certificate = generatedCertificates.get(generatedCertificates.size() - 1);
        } else {
            certificate = generatedCertificates.get(generatedCertificates.size() - 2);
        }

        certificateModifier.apply(certificate);
        VerifierResult result = testRunner.execute(generatedCertificates);
        // assert values are equal
        assert expectValid == result.isValid();
    }

    public void assertValid(X509VerifierRunner testRunner, boolean entity,
                             X509CertificateConfigModifier modifier) throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, true, entity, modifier);
    }

    public void assertInvalid(X509VerifierRunner testRunner, boolean entity,
        X509CertificateConfigModifier modifier) throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, false, entity, modifier);
    }

    public void assertValid(X509VerifierRunner testRunner, boolean entity,
        X509CertificateModifier modifier) throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, true, entity, modifier);
    }

    public void assertInvalid(X509VerifierRunner testRunner, boolean entity,
        X509CertificateModifier modifier) throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, false, entity, modifier);
    }

    public void assertValid(X509VerifierRunner testRunner, boolean entity,
        X509CertificateConfigModifier configModifier, X509CertificateModifier certificateModifier)
        throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, true, entity, configModifier, certificateModifier);
    }

    public void assertInvalid(X509VerifierRunner testRunner, boolean entity,
        X509CertificateConfigModifier configModifier, X509CertificateModifier certificateModifier)
        throws VerifierException, CertificateGeneratorException {
        assertBoolean(testRunner, false, entity, configModifier, certificateModifier);
    }

    public X509CertificateChainConfig initializeConfig() {
        return new X509CertificateChainConfig();
    }
}
