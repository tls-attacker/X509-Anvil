package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;

public class InvalidCertificateLengthTests extends X509AnvilTest {

    @Specification(document = "RFC 5280")
    @AnvilTest(id = "")
    public void shortLengthTagEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> certificate.getLengthOctets().setModifications(new ByteArrayExplicitValueModification(new byte[]{(byte) 0x82, 0, 1})));
    }

    @Specification(document = "RFC 5280")
    @AnvilTest(id = "")
    public void shortLengthTagIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> certificate.getLengthOctets().setModifications(new ByteArrayExplicitValueModification(new byte[]{(byte) 0x82, 0, 1})));
    }

    @Specification(document = "RFC 5280")
    @AnvilTest(id = "")
    public void overflowingLengthTagEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> certificate.getLengthOctets().setModifications(new ByteArrayExplicitValueModification(new byte[]{(byte) 0x82, 0x07, (byte) 0xD0})));
    }

    @Specification(document = "RFC 5280")
    @AnvilTest(id = "")
    public void overflowingLengthTagIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> certificate.getLengthOctets().setModifications(new ByteArrayExplicitValueModification(new byte[]{(byte) 0x82, 0x07, (byte) 0xD0})));
    }
}
