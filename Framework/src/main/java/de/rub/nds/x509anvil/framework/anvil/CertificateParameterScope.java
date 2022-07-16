package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;

public class CertificateParameterScope extends ParameterScope {
    private int chainPosition;
    private DerivationScope derivationScope;

    public CertificateParameterScope(int chainPosition, DerivationScope derivationScope) {
        this.chainPosition = chainPosition;
        this.derivationScope = derivationScope;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return "cert_" + chainPosition;
    }
}
