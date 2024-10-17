package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class InterCertWithoutKeyCertSignTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage",
            text = "If the keyUsage extension is present, then the subject public key MUST NOT be used to verify signatures on " +
                    "certificates or CRLs unless the corresponding keyCertSign or cRLSign bit is set.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    @AnvilTest
    public void intermediateCertWithCaNotSet(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            KeyUsageExtensionConfig keyUsageExtensionConfig = (KeyUsageExtensionConfig)
                    config.extension(ExtensionType.KEY_USAGE);
            keyUsageExtensionConfig.setKeyCertSign(false);
            keyUsageExtensionConfig.setDigitalSignature(true); // Just to make sure something is set to true
        });
        */
    }


}
