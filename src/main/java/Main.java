import de.rub.nds.asn1.model.*;
import de.rub.nds.constants.KeyType;
import de.rub.nds.exception.CertificateGeneratorException;
import de.rub.nds.util.PemUtil;
import de.rub.nds.x509.config.constants.AlgorithmObjectIdentifiers;
import de.rub.nds.x509.config.X509CertificateConfig;
import de.rub.nds.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509.config.model.*;
import de.rub.nds.x509.config.model.Signer;
import de.rub.nds.x509.generator.X509CertificateGenerator;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateGeneratorException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X509CertificateConfig certificateConfig = new X509CertificateConfig();
        certificateConfig.setSubjectPrivateKey(PemUtil.encodeKeyAsPem(keyPair.getPrivate().getEncoded(), KeyType.RSA, true));
        certificateConfig.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
        certificateConfig.setSignatureAlgorithmParameters(new Asn1Null());
        certificateConfig.setSigner(Signer.SELF);

        certificateConfig.setVersion(BigInteger.valueOf(2));
        certificateConfig.setSerialNumber(new BigInteger("123456789012345678901234567890"));
        certificateConfig.setTbsSignatureParametersType(AlgorithmParametersType.NO_PARAMETERS);
        certificateConfig.setIssuerType(IssuerType.SELF);

        certificateConfig.setNotBeforeTimeType(TimeType.UTC_TIME);
        certificateConfig.setNotBeforeValue("20220602105238Z");
        certificateConfig.setNotAfterTimeType(TimeType.UTC_TIME);
        certificateConfig.setNotAfterValue("20230602105238Z");

        Name subject = new Name();
        RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
        Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
        commonName.setValue("My Certificate");
        commonNameDN.addAttributeTypeAndValue(new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COUNTRY_NAME, commonName));
        subject.addRelativeDistinguishedName(commonNameDN);
        certificateConfig.setSubject(subject);

        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
        subjectPublicKeyInfo.setSubjectPublicKey(keyPair.getPublic().getEncoded());
        subjectPublicKeyInfo.setAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
        subjectPublicKeyInfo.setParametersType(AlgorithmParametersType.NO_PARAMETERS);
        subjectPublicKeyInfo.setParameters(new Asn1Null());
        certificateConfig.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

        certificateConfig.setExtensionsPresent(false);

        X509CertificateGenerator x509CertificateGenerator = new X509CertificateGenerator(certificateConfig);
        x509CertificateGenerator.generateCertificate();
        X509Certificate x509Certificate = x509CertificateGenerator.retrieveX509Certificate();
        System.out.println(x509Certificate);
    }
}
