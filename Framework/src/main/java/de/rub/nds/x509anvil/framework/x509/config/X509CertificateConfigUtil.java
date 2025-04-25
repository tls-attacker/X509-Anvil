/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.CertificateChainPositionType;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

import java.math.BigInteger;
import java.util.*;

public class X509CertificateConfigUtil {
    private static X509CertificateConfig generateDefaultCertificateConfig(boolean selfSigned,
                                                                          CertificateChainPositionType chainPosType, String commonName) {
        X509CertificateConfig config = new X509CertificateConfig();
        config.setSerialNumber(generateUniqueSerialNumber());
        config.setSelfSigned(selfSigned);

        // set subject
        LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, commonName));
        config.setSubject(subject);

        // add all necessary extensions
        List<ExtensionConfig> extensionConfigList = new ArrayList<>();
        extensionConfigList.add(generateBasicConstraintsConfig(chainPosType));
        extensionConfigList.add(generateKeyUsageConfig(chainPosType));
        config.setExtensions(extensionConfigList);
        config.setIncludeExtensions(true);
        return config;
    }

    public static X509CertificateConfig generateDefaultRootCaCertificateConfig(boolean selfSigned) {
        X509CertificateConfig config = generateDefaultCertificateConfig(selfSigned, CertificateChainPositionType.ROOT, "TLS Attacker CA - Global Insecurity Provider");
        attachUniqueKeysRoot(config);
        return config;
    }

    public static X509CertificateConfig generateDefaultIntermediateCaCertificateConfig(boolean selfSigned, int intermediatePosition) {
        X509CertificateConfig config = generateDefaultCertificateConfig(selfSigned, CertificateChainPositionType.INTERMEDIATE, "TLS Attacker Intermediate CA Depth " + intermediatePosition + "- Global Insecurity Provider");
        attachUniqueKeysIntermediate(config, intermediatePosition);
        return config;
    }

    public static X509CertificateConfig generateDefaultEntityCertificateConfig(boolean selfSigned) {
        X509CertificateConfig config = generateDefaultCertificateConfig(selfSigned, CertificateChainPositionType.ENTITY, "tls-attacker.com");
        // attachUniqueKeysEntity(config);
        return config;
    }


    private static BasicConstraintsConfig generateBasicConstraintsConfig(CertificateChainPositionType chainPosType) {
        BasicConstraintsConfig basicConstraintsConfig = new BasicConstraintsConfig();
        basicConstraintsConfig.setPresent(true);
        basicConstraintsConfig.setCritical(true);

        basicConstraintsConfig.setCa(chainPosType != CertificateChainPositionType.ENTITY);
        basicConstraintsConfig.setPathLenConstraint(5);
        basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.FOLLOW_DEFAULT);
        basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.FOLLOW_DEFAULT);

        return basicConstraintsConfig;
    }

    private static KeyUsageConfig generateKeyUsageConfig(CertificateChainPositionType chainPosType) {
        KeyUsageConfig keyUsageConfig = new KeyUsageConfig();
        keyUsageConfig.setPresent(true);
        keyUsageConfig.setCritical(true);
        switch (chainPosType) {
            case ROOT, INTERMEDIATE:
                keyUsageConfig.setKeyCertSign(true);
                keyUsageConfig.setDigitalSignature(true);
                keyUsageConfig.setcRLSign(true);
                keyUsageConfig.setKeyAgreement(false);
                keyUsageConfig.setKeyEncipherment(false);
                keyUsageConfig.setNonRepudiation(false);
                keyUsageConfig.setDataEncipherment(false);
                keyUsageConfig.setDecipherOnly(false);
                keyUsageConfig.setEncipherOnly(false);
                break;
            case ENTITY:
                keyUsageConfig.setKeyCertSign(false);
                keyUsageConfig.setDigitalSignature(true);
                keyUsageConfig.setcRLSign(false);
                keyUsageConfig.setKeyAgreement(true);
                keyUsageConfig.setKeyEncipherment(true);
                keyUsageConfig.setNonRepudiation(false);
                keyUsageConfig.setDataEncipherment(false);
                keyUsageConfig.setDecipherOnly(false);
                keyUsageConfig.setEncipherOnly(false);
                break;
        }
        return keyUsageConfig;
    }

    private static void attachUniqueKeysEntity(X509CertificateConfig config) {
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()), config, "entity");
    }

    private static void attachUniqueKeysRoot(X509CertificateConfig config) {
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()), config, "root");
    }

    private static void attachUniqueKeysIntermediate(X509CertificateConfig config, int intermediatePosition) {
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()), config, "inter" + intermediatePosition);
    }

    /**
     * Returns the first extension config in the given config that matches the given extensionType. Returns null if
     * extension not found.
     */
    public static ExtensionConfig getExtensionConfig(X509CertificateConfig certificateConfig,
        X509ExtensionType extensionType) {
        return certificateConfig.getExtensions().stream()
            .filter(x -> X509ExtensionType.decodeFromOidBytes(x.getExtensionId().getEncoded()) == extensionType)
            .findFirst().orElse(null);
    }

    public static X509CertificateChainConfig createBasicConfig(int chainLength) {
        X509CertificateChainConfig x509CertificateChainConfig = new X509CertificateChainConfig();
        x509CertificateChainConfig.initializeChain(chainLength, 1);
        return x509CertificateChainConfig;
    }

    public static BigInteger generateUniqueSerialNumber() {
        UUID uuid = UUID.randomUUID();
        return new BigInteger(uuid.toString().replace("-", ""), 16);
    }

    public static void modifyAttributeAndValuePair(X509CertificateConfig config, X500AttributeType type) {
        Pair<X500AttributeType, String> cnPair =
            config.getDefaultIssuer().stream().filter(x -> x.getLeftElement() == type).findFirst().orElseThrow();
        cnPair.setRightElement(cnPair.getRightElement() + "_modified");
    }
}
