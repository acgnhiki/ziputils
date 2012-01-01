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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import org.junit.Test;

/**
 *
 * @author martin
 */
public class ZipEncryptOutputStreamTest {
    /**
     * Test of read method, of class ZipDecryptInputStream.
     */
    @Test
    public void testWrite() throws Exception {
        ZipEncryptOutputStream zeos = new ZipEncryptOutputStream(new FileOutputStream("test.zip"), "password");
        ZipOutputStream zos = new ZipOutputStream(zeos);

        for (int i = 1; i < 4; i++) {
            ZipEntry ze = new ZipEntry("test" + i + ".txt");
            zos.putNextEntry(ze);
            InputStream is = getClass().getResourceAsStream("/" + ze.getName());
            int b;
            while ((b = is.read()) != -1) {
                zos.write(b);
            }
            zos.closeEntry();
        }
        zos.close();

        ZipDecryptInputStreamTest.testRead(new FileInputStream("test.zip"));
    }
}