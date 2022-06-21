/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.util;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

public class PemUtil {
    public static byte[] encodePrivateKeyAsPem(byte[] keyDer) throws IOException {
        PemObject pemObject = new PemObject("PRIVATE KEY", keyDer);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(stream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String stripWindowsLineEndings = stream.toString().replace("\r", "");
        return stripWindowsLineEndings.getBytes();
    }
}
