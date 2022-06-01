package de.rub.nds.x509.config;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.x509.config.model.*;
import org.bouncycastle.asn1.ASN1BitString;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateConfig {
    private byte[] privateKey;
    String signatureAlgorithmOid;

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
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    private boolean extensionsPresent = true;
    private List<Extension> extensions = new ArrayList<>();

    private boolean algorithmIdentifierPresent = true;
    private boolean overrideAlgorithmIdentifierOid;
    private Asn1ObjectIdentifier algorithmIdentifierOidOverridden;
    private AlgorithmParametersType algorithmIdentifierParametersType;
    // TODO: Parameters

    private boolean signaturePresent = true;
    private boolean overrideSignature;
    private ASN1BitString signatureOverridden;


    public X509CertificateConfig() {}


    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public String getSignatureAlgorithmOid() {
        return signatureAlgorithmOid;
    }

    public void setSignatureAlgorithmOid(String signatureAlgorithmOid) {
        this.signatureAlgorithmOid = signatureAlgorithmOid;
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

    public List<Extension> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<Extension> extensions) {
        this.extensions = extensions;
    }

    public boolean isExtensionsPresent() {
        return extensionsPresent;
    }

    public void setExtensionsPresent(boolean extensionsPresent) {
        this.extensionsPresent = extensionsPresent;
    }

    public boolean isAlgorithmIdentifierPresent() {
        return algorithmIdentifierPresent;
    }

    public void setAlgorithmIdentifierPresent(boolean algorithmIdentifierPresent) {
        this.algorithmIdentifierPresent = algorithmIdentifierPresent;
    }

    public boolean isOverrideAlgorithmIdentifierOid() {
        return overrideAlgorithmIdentifierOid;
    }

    public void setOverrideAlgorithmIdentifierOid(boolean overrideAlgorithmIdentifierOid) {
        this.overrideAlgorithmIdentifierOid = overrideAlgorithmIdentifierOid;
    }

    public Asn1ObjectIdentifier getAlgorithmIdentifierOidOverridden() {
        return algorithmIdentifierOidOverridden;
    }

    public void setAlgorithmIdentifierOidOverridden(Asn1ObjectIdentifier algorithmIdentifierOidOverridden) {
        this.algorithmIdentifierOidOverridden = algorithmIdentifierOidOverridden;
    }

    public AlgorithmParametersType getAlgorithmIdentifierParametersType() {
        return algorithmIdentifierParametersType;
    }

    public void setAlgorithmIdentifierParametersType(AlgorithmParametersType algorithmIdentifierParametersType) {
        this.algorithmIdentifierParametersType = algorithmIdentifierParametersType;
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
}
