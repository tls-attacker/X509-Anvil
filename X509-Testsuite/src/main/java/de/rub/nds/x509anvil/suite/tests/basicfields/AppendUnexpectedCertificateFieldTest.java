package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayInsertModification;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class AppendUnexpectedCertificateFieldTest extends X509AnvilTest {

    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void appendUnexpectedFieldEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
        octetString.setValue(TestUtils.createByteArray(8));

        assertInvalid(testRunner, true, (X509CertificateModifier)  certificate ->
                certificate.getTbsCertificate().setEncodedChildren(ArrayUtils.addAll(
                        certificate.getTbsCertificate().getEncodedChildren().getValue(),
                        octetString.getContent().getValue())));
    }

    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
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
