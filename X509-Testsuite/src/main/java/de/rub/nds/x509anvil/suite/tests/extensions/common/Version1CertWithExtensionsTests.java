package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

public class Version1CertWithExtensionsTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.extensions_present", method = "enabled")
    @AnvilTest
    public void version1CertWithExtensionsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//     TODO: re-implement when extension implemented in attacker

/*        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            config.setVersion(0);
            config.extension(ExtensionType.KEY_USAGE).setPresent(true);
        });*/
    }


    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.extensions_present", method = "enabled")
    @AnvilTest
    public void version1CertWithExtensionsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
    // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(0);
            config.extension(ExtensionType.KEY_USAGE).setPresent(true);
        }); */
   }

}
