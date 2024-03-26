/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter.name;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class NameComponentPresentParameter extends BooleanCertificateSpecificParameter {
    private final String nameComponentOid;
    private final String value;

    public NameComponentPresentParameter(ParameterIdentifier parameterIdentifier, String nameComponentOid,
        String value) {
        super(parameterIdentifier);
        this.nameComponentOid = nameComponentOid;
        this.value = value;
    }

    public NameComponentPresentParameter(Boolean selectedValue, ParameterIdentifier parameterIdentifier,
        String nameComponentOid, String value) {
        super(selectedValue, parameterIdentifier);
        this.nameComponentOid = nameComponentOid;
        this.value = value;
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        if (getSelectedValue()) {
            List<Pair<X500AttributeType, String>> name = new LinkedList<>();
            name.add(new Pair<>(Arrays.stream(X500AttributeType.values())
                .filter(x500AttributeType -> x500AttributeType.getOid().toString().equals(nameComponentOid))
                .collect(Collectors.toList()).get(0), value));
            RelativeDistinguishedName nameToAdd = new RelativeDistinguishedName("relativeDistinguishedName", name);
            certificateConfig.getSubject().addRelativeDistinguishedNames(nameToAdd);
        }
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new NameComponentPresentParameter(selectedValue, getParameterIdentifier(), nameComponentOid, value);
    }
}
