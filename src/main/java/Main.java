import de.rub.nds.asn1.model.*;
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

        String test = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIJKAIBAAKCAgEAmUnau6CTpbRylDXK1zDT4qNgFM0wq+1nVFgIu1Zo6UEcUu/a\n" +
                "80U6298H4XVJ9N0gmNROI9FIQBcQuoCoJKyqTso8dvejMWcvW/MWDZAmwXrQX8rd\n" +
                "c9LjYWuxtx4qezSmCuUybErPNuJo+DV1z3rG4udY+DxOOPWhLdG4z6TW1qZF0SGf\n" +
                "X1waW3CZS4/NYr2Qv/Ex9eJkWobrzQOXVrjKIqPHzUgTaSW0jrUda4FgcQlykYxk\n" +
                "sHbjGKO0QgIYNLhojiTQoItGZixGmApZ3BznFxNEHURGLC5B8n/H0E6qEAYsL1jw\n" +
                "H561WyEEvcOGQC+3E1VJVPVzi+PLGOMjF4DGWCzcM0d+VUJxie0qAcdgqKh3zqeW\n" +
                "slBTBXxMpSUR6PDEIwCQUyCUPputoRrjaHoQdsB1UqxJQHpyJzJOFyJ531dect9+\n" +
                "4jboXa3tVquJKwZ+TnryQeCK8lFxTBzKwz0K+aAbuzd1k1e4IngfnNouiuBmsq58\n" +
                "SkTJbKzWr0wwZMxjxwCBgUSrAjvwxnba1nc2EzowZ0l0GkewlkAH6+joeiMOBqhm\n" +
                "nCWWkDnwFlRv4iNJbpRQZhurxfVNZEZBXbfkrILy1DvEvTZH/CPFpNTLDh+Jdm8g\n" +
                "bQumcANAAWQuvznYrEmNhD7xDFwvpCVCm3e5NPXtnsZH7QC1F8LVJUGFnf0CAwEA\n" +
                "AQKCAgEAkvH6rkzz3TDLegrLJVjYdfXaAHbnRplxqaguzq+6KIjTRypJwVVHZEk8\n" +
                "u8P9Hq/wNLGpKqrQUSgLUE5PYcDoDlnOdtlT5uMcwk+Yf24FyQobwQivG/45HUXo\n" +
                "+jr/zFYfKmim2qsoU1vd9rsA8eGn0RKn9meRMQc++LaILP2/OcvxN9a8eeTIG4oo\n" +
                "WghDgnlozqfAFg9t1l5qo4Dizi6dD3Hj8oU6nlyX5wn2Zv2CXzoIS0DDsWp2r0MX\n" +
                "ZQOvArMY/9KI8K4y0XV2QwABPoGygitk641sm6PIclhOSwFuA6h3KPhgUF+LSQ2x\n" +
                "Btzt0JAtN2pVvw0BNEQtiPEMzdYTzC1sMjxXFWQa9fjWEGiBggpW1E75uPm1/YCA\n" +
                "dTbAnHujJYDZttvDV6q7uxYxZJ09dPzNMSrL59OSaZdEIUw9McgEPPE1cZEq2Mgr\n" +
                "53vuTzJJ0oY5C17C/4kBheeF634Y7jOWtynkmXFkllcuj8+x2FvQYw4d9K5YlFyt\n" +
                "lTfBFz3JoFACzd/QDc0QUEf1rpWSZbYW+gP4vyDkjCPldVdK7/Vb0mJyRiDl36WZ\n" +
                "i1VLSGpxYJlLbkj7/oujQh1oIM5ZYuDN4qRHuLJbY5hiDnFGkW+p1ISACkWW2BH7\n" +
                "uOZwkvPEzCb8EoQJmeai3WgVSyYGUQmpnvHLRPFiSmUGNndO3p0CggEBAMoYoi7v\n" +
                "P4d9y6ORcx4462U6wqn+xoYiEMp8AT+F69TQEWsFVbWp4SMyEgGEx65PQueY8foP\n" +
                "5FwG/VQAZbpmslDFA14W6gWKttLepvE0EBu39kH+FyOSfjqBDZ6H531k/oQe8YEf\n" +
                "1GyC7UYINS6wrNkbyYNlv8TdP7uCsr6ob6bRnjjxQZOpFoaV5EC0xI8/5UKOgJDb\n" +
                "qchzt6eP2OPVfpQR2RUB80EOC9ZckNt2KvEriRgHEKpZ9qiI8wBfyfnSmCiOuW3p\n" +
                "m8MaK6xnsgORjnMeYeZIM/yh9f8RANQVpxaL5JCM3RBr402yJdmvtMqHMe8CPmLO\n" +
                "76bBN+489UOfVhMCggEBAMIskm0cJdVKTutuVDnEO/k9jKpwSzEMOYEAxNthggIV\n" +
                "fFLnD7tiUEatvr36Usbp3Tg7J2RlFpJzsxnmE48gOjgaqg8HWCwqKJoHW3UWAInU\n" +
                "tHvyB4IVfDwxt/Jj0ckf6QXwYZLq605EMSRleWsxSxFXloyp1o4IVnfRQ1CM3zEy\n" +
                "aLLRcTGc51b5SVPbuhSmcUf9LTUWAzIdeh8EUOvZlXaDPRqQcPUDBSF1JNjj0ZoG\n" +
                "enMfQUEdCOQDTjsgck6DhGnnoS/HxXXzEWY5xeY3zgXlXl5oQp6jRwhzZfv4/tLi\n" +
                "cbh4zx1Kl+cYjEF3J52SFVjzau/CY+pwvmZADSdz/a8CggEAQWYnVbjmfhofRBdV\n" +
                "gXo58tBJHmnsJIvxkxT98miMIJoUiOV5DwiiaplRalxloerUY84CwEFUTNOWNxDJ\n" +
                "2sBRBAI9TL1tjc2NzD9xFq0aaV3muwRWyJQndRc+KQchylpcYrUAwiBixZq43eja\n" +
                "DPnvdXKgi3zpyfMvJKbu4PPw7bL32MV5yyb0uyjWbHoTAahTsG4c/MOY9d08mWTb\n" +
                "cx8rjw8XiMzQw0SgYAYkemCLFPBZtQTUR8xFHdTzjjNxUP7tbnKBXygx17koWOpV\n" +
                "mQIJbwdt9u92o1JmINyHwBohsBIlLQHop9/B9uqnhQJvJvsJFadMOP1uYDA2wUnI\n" +
                "tNFjMQKCAQAIt3ODTmYsYv+T9gn15edDUw4DgLL/aqsSLXSo3IG3kjtYhWLhaJJt\n" +
                "+dK8OIaKw2jY417rVNZkkKkTmo56OFoktp23uv6sTOAxue7THL+9cD0B62WG42wG\n" +
                "T70QNobuXm5Zg+b9b2pMwybpmVyQAVB7YNEzU1R8X8dx7YT2ErzaOocUr+5C6eZA\n" +
                "s0QlbZG255niP21OGsTd9RDMX6c6TzQ0c8PEc4N+nDoYvGeBDQkVvwC0Nkz5nVIO\n" +
                "2k8ivFwlRiYlku5bdL5agyTez+0gXpTzEs7fshJ7iJzhtjx3yT+3O88bFuFFUVns\n" +
                "V9/D+JNgsXQf4B2G0dUmaxVBBdMRWFWlAoIBAG95C6kcDJSzKnlhakJADWHhWda1\n" +
                "4cvW6t9YVB7ypqIFjfUYhWUNlmNso1pnC8NPC+DRLKF9Y48bg4wBDiI77+/ca9+1\n" +
                "EKb+UDH0OWCykdjj0LMy/AB1nvBn4VwG4PZcDOJ5Y8gV+SItyfooh3qWIIeomUmL\n" +
                "LwKXYz0NT74j6V2SOt/CgSHDjhHT3FRK1lQS9+vwdQeWcqbbsRJBzGzgzvIzWPKp\n" +
                "8e9mASdr1YdaM9ITHNlyHY7lS4gimlzUx1OpSTtn237bj6YLQITHLAXE6HlQglQ0\n" +
                "QD7inBSwxVc/p/ucaAg+0NT2PU2Z4sgYGlX11SDhShllLHXshNOYoHk416s=\n" +
                "-----END RSA PRIVATE KEY-----\n";

        X509CertificateConfig certificateConfig = new X509CertificateConfig();
        byte[] pemEncodedPrivateKey = PemUtil.encodePrivateKeyAsPem(keyPair.getPrivate().getEncoded());
        certificateConfig.setSubjectPrivateKey(pemEncodedPrivateKey);
        certificateConfig.setSignatureAlgorithmParameters(new Asn1Null());
        certificateConfig.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
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
