/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.x509anvil.framework.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionType;
import de.rub.nds.x509anvil.framework.x509.config.model.*;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateConfig {
    private String certificateName;

    private boolean isStatic;
    private X509Certificate staticX509Certificate;
    private boolean isSharedConfig = false;     // If this config is used for multiple certificates in a chain
    private int sharedId = 0;

    private KeyType keyType;
    private KeyPair keyPair;
    private HashAlgorithm hashAlgorithm;        // Hash algorithm used when signing another certificate with privkey

    private Signer signer;

    private Integer version;
    private BigInteger serialNumber;


    private IssuerType issuerType;
    private Name issuerOverridden;

    private TimeType notBeforeTimeType;
    private String notBeforeValue;
    private TimeType notAfterTimeType;
    private String notAfterValue;

    private Name subject;

    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    private boolean issuerUniqueIdPresent = false;
    private BitString issuerUniqueId = new BitString(new byte[0]);
    private boolean subjectUniqueIdPresent = false;
    private BitString subjectUniqueId = new BitString(new byte[0]);

    private boolean extensionsPresent = true;
    private final Map<ExtensionType, ExtensionConfig> extensions = new HashMap<>();

    public X509CertificateConfig() {
        extensions.put(ExtensionType.BASIC_CONSTRAINTS, new BasicConstraintsExtensionConfig());
        //extensions.put(ExtensionType.KEY_USAGE, new KeyUsageExtensionConfig());
    }

    public String getCertificateName() {
        return certificateName;
    }

    public void setCertificateName(String certificateName) {
        this.certificateName = certificateName;
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

    public Signer getSigner() {
        return signer;
    }

    public void setSigner(Signer signer) {
        this.signer = signer;
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

    public IssuerType getIssuerType() {
        return issuerType;
    }

    public void setIssuerType(IssuerType issuerType) {
        this.issuerType = issuerType;
    }

    public Name getIssuerOverridden() {
        return issuerOverridden;
    }

    public void setIssuerOverridden(Name issuerOverridden) {
        this.issuerOverridden = issuerOverridden;
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

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
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
            throw new IllegalArgumentException("No extension config registered for extension type " + extensionType.name());
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

        return Arrays.stream(SignatureAlgorithm.values())
                .filter(a -> a.getKeyType() == keyType && a.getHashAlgorithm() == hashAlgorithm)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Signature algorithm does not exist"));
    }

    public String getSignatureAlgorithmOid() {
        return getSignatureAlgorithm().getOid();
    }
}
