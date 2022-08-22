package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Modifiers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class InvalidPositiveVersionTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest(description = "Use a illegal positive version value")
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity.version")
    public void invalidVersion4Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, Modifiers.illegalVersionModifier(true, BigInteger.valueOf(3)));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest(description = "Use a illegal positive version value")
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0.version")
    public void invalidVersion4Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, Modifiers.illegalVersionModifier(false, BigInteger.valueOf(3)));
        Assertions.assertFalse(result.isValid());
    }
}