/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;

public class X509AnvilParameterScope extends ParameterScope {
    private final static int ROOT_CHAIN_POS = 0;
    private final static int INTER_CHAIN_OFFSET = 1;
    private final static int ENTITY_CHAIN_POS = Integer.MAX_VALUE;

    public static X509AnvilParameterScope ROOT = new X509AnvilParameterScope(ROOT_CHAIN_POS);
    public static X509AnvilParameterScope ENTITY = new X509AnvilParameterScope(ENTITY_CHAIN_POS);

    private final int chainPosition;

    public static X509AnvilParameterScope createIntermediateScope(int intermediateIndex) {
        return new X509AnvilParameterScope(INTER_CHAIN_OFFSET + intermediateIndex);
    }

    public static X509AnvilParameterScope fromUniqueIdentifier(String uniqueIdentifier) {
        if (uniqueIdentifier.equals("root")) {
            return ROOT;
        } else if (uniqueIdentifier.equals("entity")) {
            return ENTITY;
        } else if (uniqueIdentifier.startsWith("inter")) {
            int intermediateIndex = Integer.parseInt(uniqueIdentifier.replace("inter", ""));
            return new X509AnvilParameterScope(INTER_CHAIN_OFFSET + intermediateIndex);
        } else {
            throw new IllegalArgumentException("Unable to parse scope identifier " + uniqueIdentifier);
        }
    }

    private X509AnvilParameterScope(int chainPosition) {
        this.chainPosition = chainPosition;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        if (chainPosition == ROOT_CHAIN_POS) {
            return "root";
        } else if (chainPosition == ENTITY_CHAIN_POS) {
            return "entity";
        } else {
            return "inter" + (chainPosition - INTER_CHAIN_OFFSET);
        }
    }

    public boolean isRoot() {
        return chainPosition == ROOT_CHAIN_POS;
    }

    public boolean isEntity() {
        return chainPosition == ENTITY_CHAIN_POS;
    }

    public boolean isIntermediate() {
        return !isRoot() && !isEntity();
    }

    public int getIntermediateIndex() {
        if (!isIntermediate()) {
            throw new RuntimeException("Intermediate index for root or entity parameter scope requested");
        }
        return chainPosition - INTER_CHAIN_OFFSET;
    }

    public boolean isModeled(int chainLength) {
        if (isRoot()) {
            return chainLength >= 1;
        } else if (isEntity()) {
            return chainLength >= 2;
        } else {
            return chainLength >= getIntermediateIndex() + 3;
        }
    }
}
