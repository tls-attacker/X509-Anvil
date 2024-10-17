package de.rub.nds.x509anvil.suite.tests.chain;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class Version1IntermediateCertTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1.4. Preparation for Certificate i+1",
            text = "If certificate i is a version 1 or version 2 certificate, then the application MUST either verify that " +
                    "certificate i is a CA certificate through out-of-band means or reject the certificate.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @AnvilTest
    public void version1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(new BigInteger("0"));
            config.setIncludeExtensions(false);
            config.setIncludeIssuerUniqueId(false);
            config.setIncludeSubjectUniqueId(false);
        });
    }

    @Specification(document = "RFC 5280", section = "6.1.4. Preparation for Certificate i+1",
            text = "If certificate i is a version 1 or version 2 certificate, then the application MUST either verify that " +
                    "certificate i is a CA certificate through out-of-band means or reject the certificate.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @AnvilTest
    public void version2Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(new BigInteger("1"));
            config.setIncludeExtensions(false);
        });
    }

}
