/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.x509anvil.framework.constants.*;
import de.rub.nds.x509anvil.framework.x509.config.extension.*;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import org.apache.commons.lang3.NotImplementedException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateConfig {
    private String certificateName;
    private CertificateChainPosType certificateChainPosType;
    private boolean isStatic;
    private X509Certificate staticX509Certificate;
    private PrivateKeyContainer staticCertificatePrivateKey;
    private PublicKeyContent publicKey;
    private PublicKey publicKeyJavaFormat;
    private boolean isSharedConfig = false; // If this config is used for multiple certificates in a chain
    private int sharedId = 0;
    private boolean selfSigned;
    private X509SignatureAlgorithm signatureAlgorithm;
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

    public void applyKeyPair(KeyPair keyPair) {
        this.setPublicKeyJavaFormat(keyPair.getPublic());
        this.setPublicKey(X509Util.containerFromPublicKey(keyPair.getPublic()));
        this.setStaticCertificatePrivateKey(X509Util.containerFromPrivateKey(keyPair.getPrivate()));
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
        this.publicKey = staticX509Certificate.getPublicKey();
        this.signatureAlgorithm = staticX509Certificate.getX509SignatureAlgorithm();
    }

    public PrivateKeyContainer getStaticCertificatePrivateKey() {
        return staticCertificatePrivateKey;
    }

    public void setStaticCertificatePrivateKey(PrivateKeyContainer staticCertificatePrivateKey) {
        this.staticCertificatePrivateKey = staticCertificatePrivateKey;
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

    public void setSignatureAlgorithm(X509SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public PublicKeyContent getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKeyContent publicKey) {
        this.publicKey = publicKey;
    }

    public PublicKey getPublicKeyJavaFormat() {
        return publicKeyJavaFormat;
    }

    public void setPublicKeyJavaFormat(PublicKey publicKeyJavaFormat) {
        this.publicKeyJavaFormat = publicKeyJavaFormat;
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

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getSignatureAlgorithmOid() {
        return getSignatureAlgorithm().getOid().toString();
    }

    public void amendSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        if (this.signatureAlgorithm == null) {
            throw new UnsupportedOperationException("Cannot amend SignatureAlgorithm if None");
        }
        HashAlgorithm hashAlgorithm = this.signatureAlgorithm.getHashAlgorithm();
        this.signatureAlgorithm = Arrays.stream(X509SignatureAlgorithm.values())
            .filter(x -> x.getSignatureAlgorithm() == signatureAlgorithm && x.getHashAlgorithm() == hashAlgorithm)
            .findFirst().orElseThrow();
    }

    public void amendSignatureAlgorithm(HashAlgorithm hashAlgorithm) {
        if (this.signatureAlgorithm == null) {
            throw new UnsupportedOperationException("Cannot amend SignatureAlgorithm if None");
        }
        SignatureAlgorithm signatureAlgorithm = this.signatureAlgorithm.getSignatureAlgorithm();
        this.signatureAlgorithm = Arrays.stream(X509SignatureAlgorithm.values())
            .filter(x -> x.getSignatureAlgorithm() == signatureAlgorithm && x.getHashAlgorithm() == hashAlgorithm)
            .findFirst().orElseThrow();
    }

}
