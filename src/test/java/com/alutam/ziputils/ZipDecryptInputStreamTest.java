/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.alutam.ziputils;

import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author martin
 */
public class ZipDecryptInputStreamTest {
    /**
     * Test of read method, of class ZipDecryptInputStream.
     */
    @Test
    public void testRead() throws Exception {
        ZipDecryptInputStream zdis = new ZipDecryptInputStream(getClass().getResourceAsStream("/test2.zip"), "password");
        ZipInputStream zis = new ZipInputStream(zdis);

        ZipEntry ze;
        while ((ze = zis.getNextEntry()) != null) {
            InputStream is2 = getClass().getResourceAsStream("/" + ze.getName());
            int a, b;
            do {
                a = is2.read();
                b = zis.read();
                assertEquals("Files differ.", a, b);
            } while (b != -1);
            is2.close();
            zis.closeEntry();
        }
        zis.close();
    }
}