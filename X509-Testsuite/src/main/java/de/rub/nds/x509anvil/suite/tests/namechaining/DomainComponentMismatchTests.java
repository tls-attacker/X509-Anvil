package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;

public class DomainComponentMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.3. Internationalized Domain Names in Distinguished Names",
            text = "Conforming implementations shall perform a case-insensitive exact match when comparing domainComponent " +
                    "attributes in distinguished names")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-4bf3a1d933")
    public void domainComponentMismatch(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config ->
                X509CertificateConfigUtil.modifyAttributeAndValuePairInSubject(config, X500AttributeType.DOMAIN_COMPONENT)
        );
    }
}
