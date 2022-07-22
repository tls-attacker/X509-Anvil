package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.*;
import de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.linker.Linker;

import java.math.BigInteger;
import java.util.HashMap;

public class BasicConstraintsExtensionConfig extends ExtensionConfig {
    boolean caPresent = true;
    boolean ca = false;
    boolean pathLenConstraintPresent = false;
    int pathLenConstraint = 0;

    public BasicConstraintsExtensionConfig() {
        super(ExtensionObjectIdentifiers.BASIC_CONSTRAINTS, "basicConstraints");
    }

    public boolean isCaPresent() {
        return caPresent;
    }

    public void setCaPresent(boolean caPresent) {
        this.caPresent = caPresent;
    }

    public boolean isCa() {
        return ca;
    }

    public void setCa(boolean ca) {
        this.ca = ca;
    }

    public boolean isPathLenConstraintPresent() {
        return pathLenConstraintPresent;
    }

    public void setPathLenConstraintPresent(boolean pathLenConstraintPresent) {
        this.pathLenConstraintPresent = pathLenConstraintPresent;
    }

    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    @Override
    public Asn1PrimitiveOctetString getContentAsn1Structure() {
        Asn1Sequence basicConstraintsAsn1 = new Asn1Sequence();
        basicConstraintsAsn1.setIdentifier("basicConstraints");

        Asn1Boolean caAsn1 =  new Asn1Boolean();
        caAsn1.setIdentifier("ca");
        caAsn1.setValue(ca);
        basicConstraintsAsn1.addChild(caAsn1);

        if (pathLenConstraintPresent) {
            Asn1Integer pathLenConstraintAsn1 = new Asn1Integer();
            pathLenConstraintAsn1.setIdentifier("pathLenConstraint");
            pathLenConstraintAsn1.setValue(BigInteger.valueOf(pathLenConstraint));
            basicConstraintsAsn1.addChild(pathLenConstraintAsn1);
        }

        byte[] derEncoded = Asn1EncoderForX509.encode(new Linker(new HashMap<>()), basicConstraintsAsn1);

        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
