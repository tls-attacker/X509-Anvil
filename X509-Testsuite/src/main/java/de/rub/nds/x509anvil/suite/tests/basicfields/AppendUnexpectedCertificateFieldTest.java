package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.apache.commons.lang3.ArrayUtils;

public class AppendUnexpectedCertificateFieldTest extends X509AnvilTest {

    //TODO: New config value for preparator
    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
            @AnvilTest()
    public void appendUnexpectedFieldEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
        octetString.setValue(TestUtils.createByteArray(8));

        assertInvalid(testRunner, true, (X509CertificateModifier)  certificate -> {
            certificate.getTbsCertificate().setEncodedChildren(new ModifiableByteArray());
            certificate.getTbsCertificate().getEncodedChildren().setModifications(new ByteArrayExplicitValueModification(octetString.getValue().getValue()));
        });
    }

    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
            @AnvilTest()
    public void appendUnexpectedFieldIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
        octetString.setValue(TestUtils.createByteArray(8));

        assertInvalid(testRunner, false, (X509CertificateModifier)  certificate ->
                certificate.getTbsCertificate().setEncodedChildren(ArrayUtils.addAll(
                        certificate.getTbsCertificate().getEncodedChildren().getValue(),
                        octetString.getContent().getValue())));
    }
}
