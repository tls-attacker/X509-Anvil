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
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;
import de.rub.nds.x509anvil.framework.x509.config.model.*;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.bouncycastle.asn1.ASN1BitString;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateConfig {
    private boolean isStatic;
    private X509Certificate staticX509Certificate;

    private KeyPair subjectKeyPair;
    private String signatureAlgorithmOid;
    private Asn1Encodable signatureAlgorithmParameters;
    private Signer signer;
    private byte[] signaturePrivateKeyOverride;

    private boolean versionPresent = true;
    private BigInteger version;

    private boolean serialNumberPresent = true;
    private BigInteger serialNumber;

    private boolean tbsSignaturePresent = true;
    private boolean overrideTbsSignatureOid;
    private String tbsSignatureOidOverridden;
    private AlgorithmParametersType tbsSignatureParametersType;
    private Asn1Encodable tbsSignatureParameters;

    private boolean issuerPresent = true;
    private IssuerType issuerType;
    private Name issuerOverridden;

    private boolean validityPresent = true;
    private boolean notBeforePresent = true;
    private TimeType notBeforeTimeType;
    private String notBeforeValue;
    private boolean notAfterPresent = true;
    private TimeType notAfterTimeType;
    private String notAfterValue;

    private boolean subjectPresent = true;
    private Name subject;

    private boolean subjectPublicKeyInfoPresent = true;
    private boolean useKeyPair = true;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    private boolean issuerUniqueIdPresent = false;
    private BitString issuerUniqueId = new BitString(new byte[0]);
    private boolean subjectUniqueIdPresent = false;
    private BitString subjectUniqueId = new BitString(new byte[0]);

    private boolean extensionsPresent = true;
    private List<ExtensionConfig> extensions = new ArrayList<>();

    private boolean signatureAlgorithmPresent = true;
    private boolean overrideSignatureAlgorithmOid;
    private String signatureAlgorithmOidOverridden;
    private AlgorithmParametersType signatureAlgorithmParametersType;
    private Asn1Encodable algorithmIdentifiersParameters; // TODO resolve naming conflicts

    private boolean signaturePresent = true;
    private boolean overrideSignature; // TODO use in generator
    private ASN1BitString signatureOverridden;

    public X509CertificateConfig() {
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
        this.subjectKeyPair = X509Util.retrieveKeyPairFromX509Certificate(staticX509Certificate);
    }

    public KeyPair getSubjectKeyPair() {
        return subjectKeyPair;
    }

    public void setSubjectKeyPair(KeyPair subjectKeyPair) {
        this.subjectKeyPair = subjectKeyPair;
    }

    public String getSignatureAlgorithmOid() {
        return signatureAlgorithmOid;
    }

    public void setSignatureAlgorithmOid(String signatureAlgorithmOid) {
        this.signatureAlgorithmOid = signatureAlgorithmOid;
    }

    public Asn1Encodable getSignatureAlgorithmParameters() {
        return signatureAlgorithmParameters;
    }

    public void setSignatureAlgorithmParameters(Asn1Encodable signatureAlgorithmParameters) {
        this.signatureAlgorithmParameters = signatureAlgorithmParameters;
    }

    public Signer getSigner() {
        return signer;
    }

    public void setSigner(Signer signer) {
        this.signer = signer;
    }

    public byte[] getSignaturePrivateKeyOverride() {
        return signaturePrivateKeyOverride;
    }

    public void setSignaturePrivateKeyOverride(byte[] signaturePrivateKeyOverride) {
        this.signaturePrivateKeyOverride = signaturePrivateKeyOverride;
    }

    public boolean isVersionPresent() {
        return versionPresent;
    }

    public void setVersionPresent(boolean versionPresent) {
        this.versionPresent = versionPresent;
    }

    public BigInteger getVersion() {
        return version;
    }

    public void setVersion(BigInteger version) {
        this.version = version;
    }

    public boolean isSerialNumberPresent() {
        return serialNumberPresent;
    }

    public void setSerialNumberPresent(boolean serialNumberPresent) {
        this.serialNumberPresent = serialNumberPresent;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public boolean isTbsSignaturePresent() {
        return tbsSignaturePresent;
    }

    public void setTbsSignaturePresent(boolean tbsSignaturePresent) {
        this.tbsSignaturePresent = tbsSignaturePresent;
    }

    public boolean isOverrideTbsSignatureOid() {
        return overrideTbsSignatureOid;
    }

    public void setOverrideTbsSignatureOid(boolean overrideTbsSignatureOid) {
        this.overrideTbsSignatureOid = overrideTbsSignatureOid;
    }

    public String getTbsSignatureOidOverridden() {
        return tbsSignatureOidOverridden;
    }

    public void setTbsSignatureOidOverridden(String tbsSignatureOidOverridden) {
        this.tbsSignatureOidOverridden = tbsSignatureOidOverridden;
    }

    public AlgorithmParametersType getTbsSignatureParametersType() {
        return tbsSignatureParametersType;
    }

    public void setTbsSignatureParametersType(AlgorithmParametersType tbsSignatureParametersType) {
        this.tbsSignatureParametersType = tbsSignatureParametersType;
    }

    public Asn1Encodable getTbsSignatureParameters() {
        return tbsSignatureParameters;
    }

    public void setTbsSignatureParameters(Asn1Encodable tbsSignatureParameters) {
        this.tbsSignatureParameters = tbsSignatureParameters;
    }

    public boolean isIssuerPresent() {
        return issuerPresent;
    }

    public void setIssuerPresent(boolean issuerPresent) {
        this.issuerPresent = issuerPresent;
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

    public boolean isValidityPresent() {
        return validityPresent;
    }

    public void setValidityPresent(boolean validityPresent) {
        this.validityPresent = validityPresent;
    }

    public boolean isNotBeforePresent() {
        return notBeforePresent;
    }

    public void setNotBeforePresent(boolean notBeforePresent) {
        this.notBeforePresent = notBeforePresent;
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

    public boolean isNotAfterPresent() {
        return notAfterPresent;
    }

    public void setNotAfterPresent(boolean notAfterPresent) {
        this.notAfterPresent = notAfterPresent;
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

    public boolean isSubjectPresent() {
        return subjectPresent;
    }

    public void setSubjectPresent(boolean subjectPresent) {
        this.subjectPresent = subjectPresent;
    }

    public Name getSubject() {
        return subject;
    }

    public void setSubject(Name subject) {
        this.subject = subject;
    }

    public boolean isSubjectPublicKeyInfoPresent() {
        return subjectPublicKeyInfoPresent;
    }

    public void setSubjectPublicKeyInfoPresent(boolean subjectPublicKeyInfoPresent) {
        this.subjectPublicKeyInfoPresent = subjectPublicKeyInfoPresent;
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

    public List<ExtensionConfig> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionConfig> extensions) {
        this.extensions = extensions;
    }

    public boolean isExtensionsPresent() {
        return extensionsPresent;
    }

    public void setExtensionsPresent(boolean extensionsPresent) {
        this.extensionsPresent = extensionsPresent;
    }

    public boolean isSignatureAlgorithmPresent() {
        return signatureAlgorithmPresent;
    }

    public void setSignatureAlgorithmPresent(boolean signatureAlgorithmPresent) {
        this.signatureAlgorithmPresent = signatureAlgorithmPresent;
    }

    public boolean isOverrideSignatureAlgorithmOid() {
        return overrideSignatureAlgorithmOid;
    }

    public void setOverrideSignatureAlgorithmOid(boolean overrideSignatureAlgorithmOid) {
        this.overrideSignatureAlgorithmOid = overrideSignatureAlgorithmOid;
    }

    public String getSignatureAlgorithmOidOverridden() {
        return signatureAlgorithmOidOverridden;
    }

    public void setSignatureAlgorithmOidOverridden(String signatureAlgorithmOidOverridden) {
        this.signatureAlgorithmOidOverridden = signatureAlgorithmOidOverridden;
    }

    public AlgorithmParametersType getSignatureAlgorithmParametersType() {
        return signatureAlgorithmParametersType;
    }

    public void setSignatureAlgorithmParametersType(AlgorithmParametersType signatureAlgorithmParametersType) {
        this.signatureAlgorithmParametersType = signatureAlgorithmParametersType;
    }

    public Asn1Encodable getAlgorithmIdentifiersParameters() {
        return algorithmIdentifiersParameters;
    }

    public void setAlgorithmIdentifiersParameters(Asn1Encodable algorithmIdentifiersParameters) {
        this.algorithmIdentifiersParameters = algorithmIdentifiersParameters;
    }

    public boolean isSignaturePresent() {
        return signaturePresent;
    }

    public void setSignaturePresent(boolean signaturePresent) {
        this.signaturePresent = signaturePresent;
    }

    public boolean isOverrideSignature() {
        return overrideSignature;
    }

    public void setOverrideSignature(boolean overrideSignature) {
        this.overrideSignature = overrideSignature;
    }

    public ASN1BitString getSignatureOverridden() {
        return signatureOverridden;
    }

    public void setSignatureOverridden(ASN1BitString signatureOverridden) {
        this.signatureOverridden = signatureOverridden;
    }

    public boolean isUseKeyPair() {
        return useKeyPair;
    }

    public void setUseKeyPair(boolean useKeyPair) {
        this.useKeyPair = useKeyPair;
    }
}
