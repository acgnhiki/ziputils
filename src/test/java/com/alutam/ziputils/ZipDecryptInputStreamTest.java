/*
 *  Copyright 2011, 2012 Martin Matula (martin@alutam.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.alutam.ziputils;

import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Martin Matula (martin at alutam.com)
 */
public class ZipDecryptInputStreamTest {
    /**
     * Test of read method, of class ZipDecryptInputStream.
     */
    @Test
    public void testRead() throws Exception {
        testRead(getClass().getResourceAsStream("/test1.zip"));
    }

    static void testRead(InputStream input) throws Exception {
        ZipDecryptInputStream zdis = new ZipDecryptInputStream(input, "password");
        ZipInputStream zis = new ZipInputStream(zdis);

        ZipEntry ze;
        while ((ze = zis.getNextEntry()) != null) {
            InputStream is2 = ZipDecryptInputStreamTest.class.getResourceAsStream("/" + ze.getName());
            int a, b, index = 0;
            do {
                a = is2.read();
                b = zis.read();
                assertEquals("Files " + ze.getName() + " differ at offset " + index, a, b);
                index++;
            } while (b != -1);
            is2.close();
            zis.closeEntry();
        }
        zis.close();
    }
}