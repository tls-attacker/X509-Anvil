package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class WeakHashAlgorithmTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", text = "This test checks whether weak hash algorithms are supported. In this case, MD2.")
    @ChainLength(minLength = 3)
    @SeverityLevel(Severity.CRITICAL)
    public void weakHashMd2(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.amendSignatureAlgorithm(HashAlgorithm.MD2));

    }


    @Specification(document = "RFC 5280", text = "This test checks whether weak hash algorithms are supported. In this case, MD4.")
    @AnvilTest(id = "weakcrypto-fa9ccc9dfa")
    @ChainLength(minLength = 3)
    @SeverityLevel(Severity.CRITICAL)
    public void weakHashMd4(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.amendSignatureAlgorithm(HashAlgorithm.MD4));
    }


    @Specification(document = "RFC 5280", text = "This test checks whether weak hash algorithms are supported. In this case, MD5.")
    @AnvilTest(id = "weakcrypto-0499c0a19c")
    @ChainLength(minLength = 3)
    @SeverityLevel(Severity.CRITICAL)
    public void weakHashMd5(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.amendSignatureAlgorithm(HashAlgorithm.MD5));
    }


    @Specification(document = "RFC 5280", text = "This test checks whether weak hash algorithms are supported. In this case, SHA1.")
    @AnvilTest(id = "weakcrypto-dbc5ebe60a")
    @ChainLength(minLength = 3)
    @SeverityLevel(Severity.CRITICAL)
    public void weakHashSha1(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.amendSignatureAlgorithm(HashAlgorithm.SHA1));
    }

}
