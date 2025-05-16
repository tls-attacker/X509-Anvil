package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509Version;

public class BerInsteadOfDerTests extends X509AnvilTest {

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void booleanRepresentationEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> X509Util.getExtensionByOid(certificate, X509ExtensionType.KEY_USAGE).getCritical().getContent().addModification(new ByteArrayExplicitValueModification(new byte[] {0x01})));
    }

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void booleanRepresentationIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> X509Util.getExtensionByOid(certificate, X509ExtensionType.KEY_USAGE).getCritical().getContent().addModification(new ByteArrayExplicitValueModification(new byte[] {0x01})));
    }


    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void explicitVersion1Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setVersion(X509Version.V1.getValue()));
    }


    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void explicitVersion1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setVersion(X509Version.V1.getValue()));
    }

}
