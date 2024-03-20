/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.x509anvil.framework.constants.*;
import de.rub.nds.x509anvil.framework.x509.config.extension.*;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;
import de.rub.nds.x509anvil.framework.x509.config.model.Name;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateConfig {
    private String certificateName;
    private CertificateChainPosType certificateChainPosType;
    private boolean isStatic;
    private X509Certificate staticX509Certificate;
    private boolean isSharedConfig = false; // If this config is used for multiple certificates in a chain
    private int sharedId = 0;
    private boolean selfSigned;
    private KeyType keyType;
    private int keyLength;
    private KeyPair keyPair;
    private HashAlgorithm hashAlgorithm; // Hash algorithm used when signing another certificate with privkey

    private Integer version;
    private BigInteger serialNumber;
    private TimeType notBeforeTimeType;
    private String notBeforeValue;
    private TimeType notAfterTimeType;
    private String notAfterValue;
    private Name subject;
    private boolean issuerUniqueIdPresent = false;
    private BitString issuerUniqueId = new BitString(new byte[0]);
    private boolean subjectUniqueIdPresent = false;
    private BitString subjectUniqueId = new BitString(new byte[0]);
    private boolean extensionsPresent = true;
    private final Map<ExtensionType, ExtensionConfig> extensions = new HashMap<>();

    public X509CertificateConfig() {
        extensions.put(ExtensionType.AUTHORITY_KEY_IDENTIFIER, new AuthorityKeyIdentifierExtensionConfig());
        extensions.put(ExtensionType.SUBJECT_KEY_IDENTIFIER, new SubjectKeyIdentifierExtensionConfig());
        extensions.put(ExtensionType.BASIC_CONSTRAINTS, new BasicConstraintsExtensionConfig());
        extensions.put(ExtensionType.KEY_USAGE, new KeyUsageExtensionConfig());
        extensions.put(ExtensionType.UNKNOWN_EXTENSION, new UnknownExtensionConfig());
    }

    public String getCertificateName() {
        return certificateName;
    }

    public void setCertificateName(String certificateName) {
        this.certificateName = certificateName;
    }

    public CertificateChainPosType getCertificateChainPosType() {
        return certificateChainPosType;
    }

    public boolean isRoot() {
        return certificateChainPosType == CertificateChainPosType.ROOT;
    }

    public boolean isIntermediate() {
        return certificateChainPosType == CertificateChainPosType.INTERMEDIATE;
    }

    public boolean isEntity() {
        return certificateChainPosType == CertificateChainPosType.ENTITY;
    }

    public void setCertificateChainPosType(CertificateChainPosType certificateChainPosType) {
        this.certificateChainPosType = certificateChainPosType;
    }

    public boolean isStatic() {
        return isStatic;
    }

    public void setStatic(boolean isStatic) {
        this.isStatic = isStatic;
    }

    public X509Certificate getStaticX509Certificate() {
        return staticX509Certificate;
    }

    public void setStaticX509Certificate(X509Certificate staticX509Certificate) throws InvalidKeySpecException {
        this.staticX509Certificate = staticX509Certificate;
        this.keyPair = X509Util.retrieveKeyPairFromX509Certificate(staticX509Certificate);
    }

    public boolean isSharedConfig() {
        return isSharedConfig;
    }

    public void setSharedConfig(boolean sharedConfig) {
        isSharedConfig = sharedConfig;
    }

    public int getSharedId() {
        return sharedId;
    }

    public void setSharedId(int sharedId) {
        this.sharedId = sharedId;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public void setSelfSigned(boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public TimeType getNotBeforeTimeType() {
        return notBeforeTimeType;
    }

    public void setNotBeforeTimeType(TimeType notBeforeTimeType) {
        this.notBeforeTimeType = notBeforeTimeType;
    }

    public String getNotBeforeValue() {
        return notBeforeValue;
    }

    public void setNotBeforeValue(String notBeforeValue) {
        this.notBeforeValue = notBeforeValue;
    }

    public TimeType getNotAfterTimeType() {
        return notAfterTimeType;
    }

    public void setNotAfterTimeType(TimeType notAfterTimeType) {
        this.notAfterTimeType = notAfterTimeType;
    }

    public String getNotAfterValue() {
        return notAfterValue;
    }

    public void setNotAfterValue(String notAfterValue) {
        this.notAfterValue = notAfterValue;
    }

    public Name getSubject() {
        return subject;
    }

    public void setSubject(Name subject) {
        this.subject = subject;
    }

    public boolean isIssuerUniqueIdPresent() {
        return issuerUniqueIdPresent;
    }

    public void setIssuerUniqueIdPresent(boolean issuerUniqueIdPresent) {
        this.issuerUniqueIdPresent = issuerUniqueIdPresent;
    }

    public BitString getIssuerUniqueId() {
        return issuerUniqueId;
    }

    public void setIssuerUniqueId(BitString issuerUniqueId) {
        this.issuerUniqueId = issuerUniqueId;
    }

    public boolean isSubjectUniqueIdPresent() {
        return subjectUniqueIdPresent;
    }

    public void setSubjectUniqueIdPresent(boolean subjectUniqueIdPresent) {
        this.subjectUniqueIdPresent = subjectUniqueIdPresent;
    }

    public BitString getSubjectUniqueId() {
        return subjectUniqueId;
    }

    public void setSubjectUniqueId(BitString subjectUniqueId) {
        this.subjectUniqueId = subjectUniqueId;
    }

    public Map<ExtensionType, ExtensionConfig> getExtensions() {
        return extensions;
    }

    public ExtensionConfig extension(ExtensionType extensionType) {
        if (!extensions.containsKey(extensionType)) {
            throw new IllegalArgumentException(
                "No extension config registered for extension type " + extensionType.name());
        }
        return extensions.get(extensionType);
    }

    public boolean isExtensionsPresent() {
        return extensionsPresent;
    }

    public void setExtensionsPresent(boolean extensionsPresent) {
        this.extensionsPresent = extensionsPresent;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        if (isStatic) {
            switch (staticX509Certificate.getKeyInfo().getKeyType()) {
                case RSA:
                    return SignatureAlgorithm.RSA_SHA256;
                case DSA:
                    return SignatureAlgorithm.DSA_SHA256;
                case ECDSA:
                default:
                    return SignatureAlgorithm.ECDSA_SHA256;
            }
        }

        return SignatureAlgorithm.fromKeyHashCombination(keyType, hashAlgorithm);
    }

    public String getSignatureAlgorithmOid() {
        return getSignatureAlgorithm().getOid();
    }
}
