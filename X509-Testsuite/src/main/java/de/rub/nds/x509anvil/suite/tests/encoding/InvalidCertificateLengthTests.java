package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;

import java.math.BigInteger;

public class InvalidCertificateLengthTests extends X509AnvilTest {

    private static final int ADDITION = 500;

    @Specification(document = "RFC 5280")
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void shortLengthTagEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Length field is not used during preparation
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> certificate.getTbsCertificate().getLength().setModification(new BigIntegerAddModification(BigInteger.valueOf(-ADDITION))));
    }

    @Specification(document = "RFC 5280")
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void shortLengthTagIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Length field is not used during preparation
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> certificate.getTbsCertificate().getLength().setModification(new BigIntegerAddModification(BigInteger.valueOf(-ADDITION))));
    }

    @Specification(document = "RFC 5280")
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void overflowingLengthTagEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Length field is not used during preparation
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> certificate.getTbsCertificate().getLength().setModification(new BigIntegerAddModification(BigInteger.valueOf(ADDITION))));
    }

    @Specification(document = "RFC 5280")
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void overflowingLengthTagIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Length field is not used during preparation
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> certificate.getTbsCertificate().getLength().setModification(new BigIntegerAddModification(BigInteger.valueOf(ADDITION))));
    }
}
