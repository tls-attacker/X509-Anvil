package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InterCertWithoutKeyCertSignTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage",
            text = "If the keyUsage extension is present, then the subject public key MUST NOT be used to verify signatures on " +
                    "certificates or CRLs unless the corresponding keyCertSign or cRLSign bit is set.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void intermediateCertWithCaNotSet(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
            keyUsageConfig.setKeyCertSign(false);
        });
    }
}
