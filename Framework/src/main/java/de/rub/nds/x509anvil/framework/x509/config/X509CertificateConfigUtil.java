/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.*;
import de.rub.nds.x509attacker.constants.CertificateChainPositionType;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import java.math.BigInteger;
import java.util.*;

public class X509CertificateConfigUtil {

    /**
     * A counter to generate unique auth key ids. Auth key structure is
     * <prefix: 4><0x00></><intermediatePosistionBytes: 1><0x00></><counter: 9>
     */
    private static final byte[] AUTH_KEY_PREFIX = new byte[] {1, 2, 3, 4};

    /**
     * Generates a unique key identifier for the given position in the certificate chain. Increases the counter for
     * certificates.
     * @param position The intermediate position in the chain (FF for root, 00 for first intermediate, 01 for second intermediate, etc.)
     * @return A unique key identifier byte array.
     */
    private static byte[] keyIdForIntermediate(int counter, int position, boolean uniqueKeyIds) {
        byte[] keyId = new byte[16];
        System.arraycopy(AUTH_KEY_PREFIX, 0, keyId, 0, AUTH_KEY_PREFIX.length);
        keyId[4] = 0x00;
        keyId[5] = (byte) position;
        keyId[6] = 0x00;
        if (uniqueKeyIds) {
            byte[] counterBytes = BigInteger.valueOf(counter).toByteArray();
            System.arraycopy(
                    counterBytes,
                    0,
                    keyId, 7 + (9 - counterBytes.length),
                    counterBytes.length);
        } else {
            System.arraycopy(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, keyId, 7, 9);
        }
        return keyId;
    }

    /**
     * For root, always generate a static key id.
     */
    private static byte[] keyIdForRoot() {
        return keyIdForIntermediate(0, 0xFF, false);
    }

    private static byte[] keyIdForEntity(int counter, boolean uniqueKeyIds) {
        return keyIdForIntermediate(counter, 0xFE, uniqueKeyIds);
    }

    private static X509CertificateConfig generateDefaultCertificateConfig(
            boolean selfSigned, CertificateChainPositionType chainPosType, String commonName) {
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
        X509CertificateConfig config =
                generateDefaultCertificateConfig(
                        selfSigned,
                        CertificateChainPositionType.ROOT,
                        "TLS Attacker CA - Global Insecurity Provider");
        config.setSerialNumber(new BigInteger("01020304050607080910111213141516", 16));
        attachUniqueKeysRoot(config);
        SubjectKeyIdentifierConfig subjectKeyIdentifierConfig = new SubjectKeyIdentifierConfig();
        subjectKeyIdentifierConfig.setPresent(true);
        subjectKeyIdentifierConfig.setCritical(false);
        subjectKeyIdentifierConfig.setKeyIdentifier(keyIdForRoot());
        config.addExtensions(subjectKeyIdentifierConfig);
        return config;
    }

    public static X509CertificateConfig generateDefaultIntermediateCaCertificateConfig(
            boolean selfSigned, int intermediatePosition, boolean isLast, int certCounter, boolean uniqueKeyIds) {
        X509CertificateConfig config =
                generateDefaultCertificateConfig(
                        selfSigned,
                        CertificateChainPositionType.INTERMEDIATE,
                        "TLS Attacker Intermediate CA Depth "
                                + intermediatePosition
                                + "- Global Insecurity Provider");
        attachUniqueKeysIntermediate(config, intermediatePosition);
        SubjectKeyIdentifierConfig subjectKeyIdentifierConfig = new SubjectKeyIdentifierConfig();
        subjectKeyIdentifierConfig.setPresent(true);
        subjectKeyIdentifierConfig.setCritical(false);
        subjectKeyIdentifierConfig.setKeyIdentifier(keyIdForIntermediate(certCounter, intermediatePosition, uniqueKeyIds));
        config.addExtensions(subjectKeyIdentifierConfig);
        AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
        authorityKeyIdentifier.setPresent(true);
        authorityKeyIdentifier.setCritical(false);
        if (isLast) {
            // root is issuer
            authorityKeyIdentifier.setKeyIdentifier(keyIdForRoot());
        } else {
            authorityKeyIdentifier.setKeyIdentifier(keyIdForIntermediate(certCounter, intermediatePosition - 1, uniqueKeyIds));
        }
        config.addExtensions(authorityKeyIdentifier);
        return config;
    }

    public static X509CertificateConfig generateDefaultEntityCertificateConfig(boolean selfSigned, int intermediatesGenerated, int certCounter, boolean uniqueKeyIds) {
        X509CertificateConfig config = generateDefaultCertificateConfig(
                selfSigned, CertificateChainPositionType.ENTITY, "tls-attacker.com");
        AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
        authorityKeyIdentifier.setPresent(true);
        authorityKeyIdentifier.setCritical(false);
        if (intermediatesGenerated == 0) {
            // root is issuer
            authorityKeyIdentifier.setKeyIdentifier(keyIdForRoot());
        } else {
            authorityKeyIdentifier.setKeyIdentifier(keyIdForIntermediate(certCounter, intermediatesGenerated - 1, uniqueKeyIds));
        }
        SubjectKeyIdentifierConfig subjectKeyIdentifierConfig = new SubjectKeyIdentifierConfig();
        subjectKeyIdentifierConfig.setPresent(true);
        subjectKeyIdentifierConfig.setCritical(false);
        subjectKeyIdentifierConfig.setKeyIdentifier(keyIdForEntity(certCounter, uniqueKeyIds));
        config.addExtensions(subjectKeyIdentifierConfig);
        config.addExtensions(authorityKeyIdentifier);
        return config;
    }

    private static BasicConstraintsConfig generateBasicConstraintsConfig(
            CertificateChainPositionType chainPosType) {
        BasicConstraintsConfig basicConstraintsConfig = new BasicConstraintsConfig();
        basicConstraintsConfig.setPresent(true);
        basicConstraintsConfig.setCritical(true);

        basicConstraintsConfig.setCa(chainPosType != CertificateChainPositionType.ENTITY);
        basicConstraintsConfig.setPathLenConstraint(5);
        basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.FOLLOW_DEFAULT);
        basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.FOLLOW_DEFAULT);

        return basicConstraintsConfig;
    }

    private static KeyUsageConfig generateKeyUsageConfig(
            CertificateChainPositionType chainPosType) {
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
        CachedKeyPairGenerator.generateNewKeys(
                new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()),
                config,
                "entity");
    }

    private static void attachUniqueKeysRoot(X509CertificateConfig config) {
        CachedKeyPairGenerator.generateNewKeys(
                new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()),
                config,
                "root");
    }

    private static void attachUniqueKeysIntermediate(
            X509CertificateConfig config, int intermediatePosition) {
        CachedKeyPairGenerator.generateNewKeys(
                new SignatureHashAlgorithmKeyLengthPair(config.getDefaultSignatureAlgorithm()),
                config,
                "inter" + intermediatePosition);
    }

    /**
     * Returns the first extension config in the given config that matches the given extensionType.
     * Returns null if extension not found.
     */
    public static ExtensionConfig getExtensionConfig(
            X509CertificateConfig certificateConfig, X509ExtensionType extensionType) {
        return certificateConfig.getExtensions().stream()
                .filter(
                        x ->
                                X509ExtensionType.decodeFromOidBytes(
                                                x.getExtensionId().getEncoded())
                                        == extensionType)
                .findFirst()
                .orElse(null);
    }

    public static X509CertificateChainConfig createBasicConfig(int chainLength) {
        X509CertificateChainConfig x509CertificateChainConfig = new X509CertificateChainConfig();
        x509CertificateChainConfig.initializeChain(chainLength, 1, true);
        return x509CertificateChainConfig;
    }

    public static BigInteger generateUniqueSerialNumber() {
        UUID uuid = UUID.randomUUID();
        return new BigInteger(uuid.toString().replace("-", ""), 16);
    }

    public static void modifyAttributeAndValuePairInSubject(
            X509CertificateConfig config, X500AttributeType type) {
        try {
            Pair<X500AttributeType, String> existingPair =
                    config.getSubject().stream()
                            .filter(x -> x.getLeftElement() == type)
                            .findFirst()
                            .orElseThrow();
            existingPair.setRightElement(existingPair.getRightElement() + "_modified");
        } catch (NoSuchElementException e) {
            Pair<X500AttributeType, String> newPair = new Pair<>(type, "modificationtest_modified");
            List<Pair<X500AttributeType, String>> modifiableSubject =
                    new ArrayList<>(config.getSubject());
            modifiableSubject.add(newPair);
            config.setSubject(modifiableSubject);
        }
    }
}
