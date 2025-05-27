package de.rub.nds.x509anvil.suite.tests.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.StaticRoot;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.ArrayList;
import java.util.List;

public class UntrustedRootTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", text = "If the root certificate is not trusted, the certificate MUST be rejected.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2)
    @AnvilTest(id = "common-f15e7199ea")
    @StaticRoot(false)
    public void untrustedRootCertificate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertBooleanRoot(testRunner, false, config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.set(0, new Pair<>(subject.get(0).getLeftElement(), subject.get(0).getRightElement() + " Untrusted"));
            config.setSubject(subject);
        });
    }
}
