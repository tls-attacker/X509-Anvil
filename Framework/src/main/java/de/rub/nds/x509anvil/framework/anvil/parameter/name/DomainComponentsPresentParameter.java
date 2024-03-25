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
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.BooleanCertificateSpecificParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

import java.util.LinkedList;
import java.util.List;

public class DomainComponentsPresentParameter extends BooleanCertificateSpecificParameter {

    public DomainComponentsPresentParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.DOMAIN_COMPONENTS_PRESENT, parameterScope));
    }

    public DomainComponentsPresentParameter(Boolean selectedValue, ParameterScope parameterScope) {
        super(selectedValue, new ParameterIdentifier(X509AnvilParameterType.DOMAIN_COMPONENTS_PRESENT, parameterScope));
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        if (getSelectedValue()) {
            List<Pair<X500AttributeType, String>> name = new LinkedList<>();
            name.add(new Pair<>(X500AttributeType.COMMON_NAME, "x509anvil"));
            name.add(new Pair<>(X500AttributeType.ORGANISATION_UNIT_NAME, "nds"));
            name.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "rub"));
            name.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "de"));
            RelativeDistinguishedName commonNameDN = new RelativeDistinguishedName("relativeDistinguishedName", name);
            certificateConfig.getSubject().addRelativeDistinguishedNames(commonNameDN);
        }
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, Boolean> generateValue(Boolean selectedValue) {
        return new DomainComponentsPresentParameter(selectedValue, getParameterScope());
    }
}
