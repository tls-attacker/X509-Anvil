/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;

import java.math.BigInteger;

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
    public Asn1PrimitiveOctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) {
        Asn1Sequence basicConstraintsAsn1 = new Asn1Sequence();

        Asn1Boolean caAsn1 = new Asn1Boolean();
        caAsn1.setIdentifier("ca");
        caAsn1.setValue(ca);
        basicConstraintsAsn1.addChild(caAsn1);

        if (pathLenConstraintPresent) {
            Asn1Integer pathLenConstraintAsn1 = new Asn1Integer();
            pathLenConstraintAsn1.setIdentifier("pathLenConstraint");
            pathLenConstraintAsn1.setValue(BigInteger.valueOf(pathLenConstraint));
            basicConstraintsAsn1.addChild(pathLenConstraintAsn1);
        }

        Asn1FieldSerializer serializer = new Asn1FieldSerializer(basicConstraintsAsn1);
        byte[] derEncoded = serializer.serialize();

        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
