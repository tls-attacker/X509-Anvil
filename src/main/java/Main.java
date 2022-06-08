import de.rub.nds.asn1.model.*;
import de.rub.nds.exception.CertificateGeneratorException;
import de.rub.nds.util.PemUtil;
import de.rub.nds.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509.config.constants.AlgorithmObjectIdentifiers;
import de.rub.nds.x509.config.X509CertificateConfig;
import de.rub.nds.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509.config.model.*;
import de.rub.nds.x509.config.model.Signer;
import de.rub.nds.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509.generator.X509CertificateGenerator;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.List;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateGeneratorException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        Registry.getInstance();

        X509CertificateChainConfig certificateChainConfig = new X509CertificateChainConfig();

        // Self-signed root certificate
        {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509CertificateConfig rootConfig = new X509CertificateConfig();
            byte[] pemEncodedPrivateKey = PemUtil.encodePrivateKeyAsPem(keyPair.getPrivate().getEncoded());
            rootConfig.setSubjectPrivateKey(pemEncodedPrivateKey);
            rootConfig.setSignatureAlgorithmParameters(new Asn1Null());
            rootConfig.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
            rootConfig.setSigner(Signer.SELF);

            rootConfig.setVersion(BigInteger.valueOf(2));
            rootConfig.setSerialNumber(new BigInteger("123456789012345678901234567890"));
            rootConfig.setTbsSignatureParametersType(AlgorithmParametersType.NO_PARAMETERS);
            rootConfig.setIssuerType(IssuerType.SELF);

            rootConfig.setNotBeforeTimeType(TimeType.UTC_TIME);
            rootConfig.setNotBeforeValue("20220602105238Z");
            rootConfig.setNotAfterTimeType(TimeType.UTC_TIME);
            rootConfig.setNotAfterValue("20230602105238Z");

            Name subject = new Name();
            RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
            Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
            commonName.setValue("My Root Certificate");
            commonNameDN.addAttributeTypeAndValue(new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COUNTRY_NAME, commonName));
            subject.addRelativeDistinguishedName(commonNameDN);
            rootConfig.setSubject(subject);

            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
            subjectPublicKeyInfo.setSubjectPublicKey(keyPair.getPublic().getEncoded());
            subjectPublicKeyInfo.setAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
            subjectPublicKeyInfo.setParametersType(AlgorithmParametersType.NO_PARAMETERS);
            subjectPublicKeyInfo.setParameters(new Asn1Null());
            rootConfig.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

            rootConfig.setExtensionsPresent(false);

            certificateChainConfig.addCertificateConfig(rootConfig);
        }


        // Entity certificate config
        {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509CertificateConfig entityConfig = new X509CertificateConfig();
            byte[] pemEncodedPrivateKey = PemUtil.encodePrivateKeyAsPem(keyPair.getPrivate().getEncoded());
            entityConfig.setSubjectPrivateKey(pemEncodedPrivateKey);
            entityConfig.setSignatureAlgorithmParameters(new Asn1Null());
            entityConfig.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
            entityConfig.setSigner(Signer.NEXT_IN_CHAIN);

            entityConfig.setVersion(BigInteger.valueOf(2));
            entityConfig.setSerialNumber(new BigInteger("123456789012345678901234567890"));
            entityConfig.setTbsSignatureParametersType(AlgorithmParametersType.NO_PARAMETERS);
            entityConfig.setIssuerType(IssuerType.NEXT_IN_CHAIN);

            entityConfig.setNotBeforeTimeType(TimeType.UTC_TIME);
            entityConfig.setNotBeforeValue("20220602105238Z");
            entityConfig.setNotAfterTimeType(TimeType.UTC_TIME);
            entityConfig.setNotAfterValue("20230602105238Z");

            Name subject = new Name();
            RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
            Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
            commonName.setValue("My Leaf Certificate");
            commonNameDN.addAttributeTypeAndValue(new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COUNTRY_NAME, commonName));
            subject.addRelativeDistinguishedName(commonNameDN);
            entityConfig.setSubject(subject);

            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo();
            subjectPublicKeyInfo.setSubjectPublicKey(keyPair.getPublic().getEncoded());
            subjectPublicKeyInfo.setAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
            subjectPublicKeyInfo.setParametersType(AlgorithmParametersType.NO_PARAMETERS);
            subjectPublicKeyInfo.setParameters(new Asn1Null());
            entityConfig.setSubjectPublicKeyInfo(subjectPublicKeyInfo);

            entityConfig.setExtensionsPresent(false);

            certificateChainConfig.addCertificateConfig(entityConfig);
        }


        X509CertificateChainGenerator x509CertificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        x509CertificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificates = x509CertificateChainGenerator.retrieveCertificateChain();


        System.out.println(certificates.size());
    }
}
