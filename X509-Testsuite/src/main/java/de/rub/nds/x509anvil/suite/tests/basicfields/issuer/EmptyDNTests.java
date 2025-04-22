package de.rub.nds.x509anvil.suite.tests.basicfields.issuer;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import java.util.List;

public class EmptyDNTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.4. Issuer", text = "The issuer field MUST contain a non-empty distinguished name (DN).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(id = "empty_dn")
    public void emptyDn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: What does "empty" actually mean?
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config ->
                config.setIssuer(List.of(new Pair<>(X500AttributeType.DN_QUALIFIER, "empty")))
        );
    }
}
