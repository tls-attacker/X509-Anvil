/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.util;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Base64;

public class PemUtil {
    public static byte[] encodeKeyAsPem(byte[] keyDer, String type) throws IOException {
        PemObject pemObject = new PemObject(type, keyDer);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(stream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String stripWindowsLineEndings = stream.toString().replace("\r", "");
        return stripWindowsLineEndings.getBytes();
    }

    public static byte[] pemToDer(byte[] pemBytes) {
        String pem = new String(pemBytes);
        pem = pem.replaceAll("-----.+-----", "").replaceAll(System.lineSeparator(), "").replaceAll("\n", "");
        return Base64.getDecoder().decode(pem);
    }
}
