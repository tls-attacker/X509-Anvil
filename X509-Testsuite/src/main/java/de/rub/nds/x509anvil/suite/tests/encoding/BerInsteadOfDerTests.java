package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509Version;

public class BerInsteadOfDerTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-0e88c639e4")
    public void booleanRepresentationEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setCritical(true);
            basicConstraintsConfig.setInvalidCriticalEncoding(true);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-5735cdbb46")
    public void booleanRepresentationIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setCritical(true);
            basicConstraintsConfig.setInvalidCriticalEncoding(true);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-bbe8f26bc7")
    public void explicitVersion1Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setVersion(X509Version.V1.getValue()));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-42c061c4d3")
    public void explicitVersion1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setVersion(X509Version.V1.getValue()));
    }

}
