package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class NegativeVersionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest()
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    public void negativeVersionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, true,
        (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(-1)));
    }

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest()
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)

    public void negativeVersionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false,
        (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(-1)));
    }
}
