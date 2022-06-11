package de.rub.nds.x509anvil.x509.config.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.exception.CertificateGeneratorException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;

public class SubjectPublicKeyInfo implements Asn1Structure<Asn1Sequence> {
    private String algorithmOid;
    private AlgorithmParametersType parametersType;
    private Asn1Encodable parameters;
    private boolean subjectPublicKeyPresent = true;
    private byte[] subjectPublicKey;
    private int subjectPublicKeyUnusedBytes;

    public SubjectPublicKeyInfo() {}

    public SubjectPublicKeyInfo(String algorithmOid, AlgorithmParametersType parametersType, Asn1Encodable parameters,
                                boolean subjectPublicKeyPresent, byte[] subjectPublicKey, int subjectPublicKeyUnusedBytes) {
        this.algorithmOid = algorithmOid;
        this.parametersType = parametersType;
        this.parameters = parameters;
        this.subjectPublicKeyPresent = subjectPublicKeyPresent;
        this.subjectPublicKey = subjectPublicKey;
        this.subjectPublicKeyUnusedBytes = subjectPublicKeyUnusedBytes;
    }

    public String getAlgorithmOid() {
        return algorithmOid;
    }

    public void setAlgorithmOid(String algorithmOid) {
        this.algorithmOid = algorithmOid;
    }

    public AlgorithmParametersType getParametersType() {
        return parametersType;
    }

    public void setParametersType(AlgorithmParametersType parametersType) {
        this.parametersType = parametersType;
    }

    public Asn1Encodable getParameters() {
        return parameters;
    }

    public void setParameters(Asn1Encodable parameters) {
        this.parameters = parameters;
    }

    public boolean isSubjectPublicKeyPresent() {
        return subjectPublicKeyPresent;
    }

    public void setSubjectPublicKeyPresent(boolean subjectPublicKeyPresent) {
        this.subjectPublicKeyPresent = subjectPublicKeyPresent;
    }

    public byte[] getSubjectPublicKey() {
        return subjectPublicKey;
    }

    public void setSubjectPublicKey(byte[] subjectPublicKey) {
        this.subjectPublicKey = subjectPublicKey;
    }

    public int getSubjectPublicKeyUnusedBytes() {
        return subjectPublicKeyUnusedBytes;
    }

    public void setSubjectPublicKeyUnusedBytes(int subjectPublicKeyUnusedBytes) {
        this.subjectPublicKeyUnusedBytes = subjectPublicKeyUnusedBytes;
    }

    @Override
    public Asn1Sequence getAsn1Structure(String identifier) throws CertificateGeneratorException {
        Asn1Sequence subjectPublicKeyInfo = new Asn1Sequence();
        subjectPublicKeyInfo.setIdentifier("subjectPublicKeyInfo");

        Asn1Sequence algorithm = new Asn1Sequence();
        algorithm.setIdentifier("algorithm");

        Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier();
        oid.setIdentifier("algorithm");
        oid.setValue(algorithmOid);
        algorithm.addChild(oid);

        switch (parametersType) {
            case NULL_PARAMETER:
                Asn1Null asn1Null = new Asn1Null();
                asn1Null.setIdentifier("parameters");
                algorithm.addChild(asn1Null);
                break;
            case PARAMETERS_PRESENT:
                try {
                    Asn1Encodable parametersAsn1 = parameters.getCopy();
                    parametersAsn1.setIdentifier("parameters");
                    algorithm.addChild(parametersAsn1);
                } catch (JAXBException | IOException | XMLStreamException e) {
                    throw new CertificateGeneratorException("Unable to copy algorithm parameters field from config", e);
                }
                break;
            default:
                // Don't add parameters to sequence
                break;
        }

        subjectPublicKeyInfo.addChild(algorithm);

        if (subjectPublicKeyPresent) {
            Asn1PrimitiveBitString subjectPublicKeyBits = new Asn1PrimitiveBitString();
            subjectPublicKeyBits.setIdentifier("subjectPublicKey");
            subjectPublicKeyBits.setValue(subjectPublicKey);
            subjectPublicKeyBits.setUnusedBits(subjectPublicKeyUnusedBytes);
            subjectPublicKeyInfo.addChild(subjectPublicKeyBits);
        }

        return subjectPublicKeyInfo;
    }
}
