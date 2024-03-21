/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.constants.CertificateChainPosType;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.parser.X509Parser;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.UUID;

public class X509CertificateConfigUtil {
    public static X509CertificateConfig getDefaultCertificateConfig(String certificateName, boolean selfSigned,
        CertificateChainPosType chainPosType) {
        X509CertificateConfig config = new X509CertificateConfig();

        config.setCertificateName(certificateName);
        config.setCertificateChainPosType(chainPosType);
        config.setKeyType(KeyType.RSA);
        config.setKeyLength(2048);
        config.setHashAlgorithm(HashAlgorithm.SHA256);
        config.setKeyPair(generateKeyPair(KeyType.RSA, certificateName, 2048));
        config.setSelfSigned(selfSigned);

        config.setVersion(2);
        config.setSerialNumber(generateUniqueSerialNumber());

        config.setNotBeforeTimeType(TimeType.UTC_TIME);
        config.setNotBeforeValue("220101000000Z");
        config.setNotAfterTimeType(TimeType.UTC_TIME);
        config.setNotAfterValue("320101000000Z");

        // TODO: identifier?
        Name subject = new Name();
        RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName();
        Asn1PrimitivePrintableString commonName = new Asn1PrimitivePrintableString();
        commonName.setValue(certificateName);
        commonNameDN.addAttributeTypeAndValue(
            new AttributeTypeAndValue(id, X500AttributeType.COMMON_NAME, commonName.getValue()));
        subject.addRelativeDistinguishedNames(commonNameDN);
        config.setSubject(subject);

        config.setExtensionsPresent(false);

        return config;
    }

    public static X509CertificateConfig getDefaultCaCertificateConfig(String certificateName, boolean selfSigned,
        CertificateChainPosType chainPosType) {
        X509CertificateConfig config = getDefaultCertificateConfig(certificateName, selfSigned, chainPosType);

        config.setExtensionsPresent(true);
        BasicConstraintsExtensionConfig basicConstraints =
            (BasicConstraintsExtensionConfig) config.extension(ExtensionType.BASIC_CONSTRAINTS);
        basicConstraints.setPresent(true);
        basicConstraints.setCa(true);
        basicConstraints.setPathLenConstraintPresent(false);

        KeyUsageExtensionConfig keyUsage = (KeyUsageExtensionConfig) config.extension(ExtensionType.KEY_USAGE);
        keyUsage.setPresent(true);
        keyUsage.setKeyCertSign(true);

        return config;
    }

    public static X509CertificateChainConfig createBasicConfig(int chainLength) {
        X509CertificateChainConfig x509CertificateChainConfig = new X509CertificateChainConfig();
        x509CertificateChainConfig.initializeChain(chainLength, 1,
            ContextHelper.getTestConfig().getUseStaticRootCertificate());
        return x509CertificateChainConfig;
    }

    public static KeyPair generateKeyPair(KeyType keyType, String keyPairIdentifier) {
        int defaultKeySize = keyType == KeyType.ECDSA ? 256 : 2048;
        return generateKeyPair(keyType, keyPairIdentifier, defaultKeySize);
    }

    public static KeyPair generateKeyPair(KeyType keyType, String keyPairIdentifier, int keyLength) {
        try {
            return CachedKeyPairGenerator.retrieveKeyPair(keyPairIdentifier, keyType.name(), keyLength);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("This should not happen");
        }
    }

    public static X509CertificateConfig loadStaticCertificateConfig(String staticCertificateFile, String privateKeyFile)
        throws IOException, InvalidKeySpecException {
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

    public static Iterable<X509CertificateConfig>
        expandCertificateConfigs(X509CertificateChainConfig certificateChainConfig) {
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
                } else if (i > 0 && i < certificateChainConfig.getChainLength() - 1) {
                    if (i - 1 < certificateChainConfig.getIntermediateCertsModeled()) {
                        // Intermediate certificate is modeled, return config
                        return certificateChainConfig.getIntermediateCertificateConfigs().get(i - 1);
                    } else {
                        // Intermediate certificate is not modeled, copy config of last modeled intermediate cert
                        return certificateChainConfig.getIntermediateCertificateConfigs()
                            .get(certificateChainConfig.getIntermediateCertsModeled() - 1);
                    }
                } else if (i == certificateChainConfig.getChainLength() - 1) {
                    return certificateChainConfig.getEntityCertificateConfig();
                } else {
                    throw new IndexOutOfBoundsException();
                }
            }
        };
    }
}
