/*
 *  Copyright 2011 Martin Matula (martin@alutam.com)
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
 * @author martin
 */
public class ZipDecryptInputStreamTest {
    /**
     * Test of read method, of class ZipDecryptInputStream.
     */
    @Test
    public void testRead() throws Exception {
        ZipDecryptInputStream zdis = new ZipDecryptInputStream(getClass().getResourceAsStream("/test1.zip"), "password");
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