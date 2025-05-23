package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class UnknownCriticalExtensionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @IpmLimitations(identifiers = {"entity:version", "entity:extensions_present", "entity:ext_unknown_noncritical_extension_present"})
    @AnvilTest(id = "")
    public void unknownCriticalExtensionEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            UnknownConfig unknownConfig = new UnknownConfig(X509ExtensionType.UNKNOWN.getOid(), "unknownExtension");
            unknownConfig.setCritical(true);
            unknownConfig.setPresent(true);
            unknownConfig.setContent(new byte[] {10, 11, 12});
            config.addExtensions(unknownConfig);
        });
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @IpmLimitations(identifiers = {"inter0:version", "inter0:extensions_present", "inter0:ext_unknown_noncritical_extension_present"})
    @AnvilTest(id = "")
    public void unknownCriticalExtensionIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            UnknownConfig unknownConfig = new UnknownConfig(X509ExtensionType.UNKNOWN.getOid(), "unknownExtension");
            unknownConfig.setCritical(true);
            unknownConfig.setPresent(true);
            unknownConfig.setContent(new byte[] {10, 11, 12});
            config.addExtensions(unknownConfig);
        });
    }

}
