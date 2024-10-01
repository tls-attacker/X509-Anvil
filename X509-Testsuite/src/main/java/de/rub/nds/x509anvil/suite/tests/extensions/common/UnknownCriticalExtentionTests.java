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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class UnknownCriticalExtentionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"entity.version", "entity.extensions_present", "entity.ext_unknown_noncritical_extension_present"})
    @AnvilTest
    public void unknownCriticalExtensionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//   TODO: re-implement when extension is implemented
        /*     assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
            config.setVersion(2);
            config.setExtensionsPresent(true);
            config.extension(ExtensionType.UNKNOWN_EXTENSION).setPresent(true);
            config.extension(ExtensionType.UNKNOWN_EXTENSION).setCritical(true);
        });
    */
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"inter0.version", "inter0.extensions_present", "inter0.ext_unknown_noncritical_extension_present"})
    @AnvilTest

    public void unknownCriticalExtensionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
    /*    assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(2);
            config.setExtensionsPresent(true);
            config.extension(ExtensionType.UNKNOWN_EXTENSION).setPresent(true);
            config.extension(ExtensionType.UNKNOWN_EXTENSION).setCritical(true);
        });

     */
    }

}
