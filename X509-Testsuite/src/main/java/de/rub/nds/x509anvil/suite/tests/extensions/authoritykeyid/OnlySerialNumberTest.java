package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;

import java.math.BigInteger;

public class OnlySerialNumberTest extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-b054d544c3")
    public void missingKeyIdentifierEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setSerialNumber(1024);
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            config.setSerialNumber(BigInteger.valueOf(1024));
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-dadc51d905")
    public void missingKeyIdentifierIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setSerialNumber(1024);
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            config.setSerialNumber(BigInteger.valueOf(1024));
        });
    }
}
