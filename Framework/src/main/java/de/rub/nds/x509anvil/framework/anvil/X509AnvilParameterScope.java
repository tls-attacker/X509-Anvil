package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;

import java.util.Objects;

public class X509AnvilParameterScope extends ParameterScope {
    private final int chainPosition;

    public static X509AnvilParameterScope fromUniqueIdentifier(String uniqueIdentifier) throws NumberFormatException {
        String withoutPrefix = uniqueIdentifier.replace("cert_", "");
        int chainPosition = Integer.parseInt(withoutPrefix);
        return new X509AnvilParameterScope(chainPosition);
    }

    public X509AnvilParameterScope(int chainPosition) {
        this.chainPosition = chainPosition;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return "cert_" + chainPosition;
    }

    public int getChainPosition() {
        return chainPosition;
    }
}
