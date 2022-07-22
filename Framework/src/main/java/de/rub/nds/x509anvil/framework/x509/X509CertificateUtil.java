/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.parser.X509Parser;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.x509.config.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.AlgorithmObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.*;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.UUID;

public class X509CertificateUtil {
    public static X509CertificateConfig getDefaultCertificateConfig(String cn, boolean selfSigned) {
        KeyPair keyPair;
        try {
            keyPair = CachedKeyPairGenerator.retrieveKeyPair(cn, "RSA", 4096);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("This should not happen");
        }

        X509CertificateConfig config = new X509CertificateConfig();

        config.setKeyPair(keyPair);
        config.setSignatureAlgorithmParameters(new Asn1Null());
        config.setSignatureAlgorithmOid(AlgorithmObjectIdentifiers.SHA256_WITH_RSA_ENCRYPTION);
        if (selfSigned) {
            config.setSigner(Signer.SELF);
        } else {
            config.setSigner(Signer.CA);
        }

        config.setVersion(2);
        config.setSerialNumber(generateUniqueSerialNumber());
        config.setTbsSignatureParametersType(AlgorithmParametersType.NO_PARAMETERS);
        if (selfSigned) {
            config.setIssuerType(IssuerType.SELF);
        } else {
            config.setIssuerType(IssuerType.NEXT_IN_CHAIN);
        }

        config.setNotBeforeTimeType(TimeType.UTC_TIME);
        config.setNotBeforeValue("220101000000Z");
        config.setNotAfterTimeType(TimeType.UTC_TIME);
        config.setNotAfterValue("320101000000Z");

        Name subject = new Name();
        RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
        Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
        commonName.setValue(cn);
        commonNameDN.addAttributeTypeAndValue(
            new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COMMON_NAME, commonName));
        subject.addRelativeDistinguishedName(commonNameDN);
        config.setSubject(subject);

        config.setExtensionsPresent(false);

        return config;
    }

    public static KeyPair generateKeyPair(KeyType keyType, String keyPairIdentifier) {
        int defaultKeySize = keyType == KeyType.DSA ? 256 : 2048;
        try {
            return CachedKeyPairGenerator.retrieveKeyPair(keyPairIdentifier, keyType.name(), defaultKeySize);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("This should not happen");
        }
    }

    public static X509CertificateConfig loadStaticCertificateConfig(String staticCertificateFile, String privateKeyFile) throws IOException, InvalidKeySpecException {
        X509Parser x509Parser = new X509Parser(new File(staticCertificateFile));
        X509Certificate staticRootCertificate = x509Parser.parse();
        staticRootCertificate.setKeyFile(new File(privateKeyFile));
        X509CertificateConfig staticX509CertificateConfig = new X509CertificateConfig();
        staticX509CertificateConfig.setStatic(true);
        staticX509CertificateConfig.setStaticX509Certificate(staticRootCertificate);
        return staticX509CertificateConfig;
    }

    public static BigInteger generateUniqueSerialNumber() {
        UUID uuid = UUID.randomUUID();
        return new BigInteger(uuid.toString().replace("-", ""), 16);
    }

    public static Iterable<X509CertificateConfig> expandCertificateConfigs(X509CertificateChainConfig certificateChainConfig) {
        return () -> new Iterator<X509CertificateConfig>() {
            private int currentIndex = 0;

            @Override
            public boolean hasNext() {
                return currentIndex < certificateChainConfig.getChainLength();
            }

            @Override
            public X509CertificateConfig next() {
                int i = currentIndex++;
                if (i == 0) {
                    return certificateChainConfig.getRootCertificateConfig();
                }
                else if (i > 0 && i < certificateChainConfig.getChainLength() - 1) {
                    if (i - 1 < certificateChainConfig.getIntermediateCertsModeled()) {
                        // Intermediate certificate is modeled, return config
                        return certificateChainConfig.getIntermediateCertificateConfigs().get(i - 1);
                    }
                    else {
                        // Intermediate certificate is not modeled, copy config of last modeled intermediate cert
                        return certificateChainConfig.getIntermediateCertificateConfigs().get(certificateChainConfig.getIntermediateCertsModeled()-1);
                    }
                }
                else if (i == certificateChainConfig.getChainLength() - 1) {
                    return certificateChainConfig.getEntityCertificateConfig();
                }
                else {
                    throw new IndexOutOfBoundsException();
                }
            }
        };
    }
}
