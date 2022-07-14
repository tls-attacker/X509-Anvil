
/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilModelBasedIpmFactory;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterFactory;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;

public class Main {
    public static void main(String[] args) {
        AnvilContext.getInstance().addParameterTypes(X509AnvilParameterType.values(), new X509AnvilParameterFactory());
        AnvilContext.getInstance().setModelBasedIpmFactory(new X509AnvilModelBasedIpmFactory());
        AnvilContext.getInstance()
            .setApplicationSpecificContextDelegate(new X509AnvilContextDelegate(new TestConfig()));
    }
}
