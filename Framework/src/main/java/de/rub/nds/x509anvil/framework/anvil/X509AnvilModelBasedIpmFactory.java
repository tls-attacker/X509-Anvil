package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.ModelBasedIpmFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;

import java.util.List;

public class X509AnvilModelBasedIpmFactory extends ModelBasedIpmFactory {
    @Override
    protected List<ParameterIdentifier> getAllParameterIdentifiers(DerivationScope derivationScope) {
        return null;
    }
}
