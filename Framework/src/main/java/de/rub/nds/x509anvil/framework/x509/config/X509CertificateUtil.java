package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.x509anvil.framework.x509.config.constants.AlgorithmObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class X509CertificateUtil {
    public static X509CertificateConfig getDefaultCertificateConfig(boolean selfSigned) {
        // Generate key pair
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("This should not happen", e);
        }

        X509CertificateConfig config = new X509CertificateConfig();

        config.setSubjectKeyPair(keyPair);
        config.setSignatureAlgorithmParameters(new Asn1Null());
        config.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
        if (selfSigned) {
            config.setSigner(Signer.SELF);
        } else {
            config.setSigner(Signer.NEXT_IN_CHAIN);
        }

        config.setVersion(BigInteger.valueOf(2));
        config.setSerialNumber(generateUniqueSerialNumber());
        config.setTbsSignatureParametersType(AlgorithmParametersType.NO_PARAMETERS);
        if (selfSigned) {
            config.setIssuerType(IssuerType.SELF);
        } else {
            config.setIssuerType(IssuerType.NEXT_IN_CHAIN);
        }

        config.setNotBeforeTimeType(TimeType.UTC_TIME);
        config.setNotBeforeValue("20220101000000Z");
        config.setNotAfterTimeType(TimeType.UTC_TIME);
        config.setNotAfterValue("20320101000000Z");

        Name subject = new Name();
        RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
        Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
        commonName.setValue("Certificate Generated with Default Configuration");
        commonNameDN.addAttributeTypeAndValue(
                new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COUNTRY_NAME, commonName));
        subject.addRelativeDistinguishedName(commonNameDN);
        config.setSubject(subject);

        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
        subjectPublicKeyInfo.setSubjectPublicKey(keyPair.getPublic().getEncoded());
        subjectPublicKeyInfo.setAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
        subjectPublicKeyInfo.setParametersType(AlgorithmParametersType.NO_PARAMETERS);
        subjectPublicKeyInfo.setParameters(new Asn1Null());
        config.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        config.setExtensionsPresent(false);

        return config;
    }

    public static BigInteger generateUniqueSerialNumber() {
        UUID uuid = UUID.randomUUID();
        return new BigInteger(uuid.toString().replace("-", ""), 16);
    }
}
