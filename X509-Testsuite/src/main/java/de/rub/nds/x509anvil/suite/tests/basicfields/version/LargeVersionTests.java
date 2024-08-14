package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class LargeVersionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest()
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity.version")
    public void largeVersionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        certificateChainConfig.getEntityCertificateConfig().setVersion(new BigInteger("256"));
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest()
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0.version")
    public void largeVersionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        certificateChainConfig.getEntityCertificateConfig().setVersion(new BigInteger("256"));
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
