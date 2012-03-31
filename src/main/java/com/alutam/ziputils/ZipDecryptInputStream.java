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

import java.io.IOException;
import java.io.InputStream;
import static com.alutam.ziputils.ZipUtil.*;

/**
 * Input stream converting a password-protected zip to an unprotected zip.
 *
 * <h3>Example usage:</h3>
 * <p>Reading a password-protected zip from file:</p>
 * <pre>
 *  ZipDecryptInputStream zdis = new ZipDecryptInputStream(new FileInputStream(fileName), password);
 *  ZipInputStream zis = new ZipInputStream(zdis);
 *  ... read the zip file from zis - the standard JDK ZipInputStream ...
 * </pre>
 * <p>Converting a password-protected zip file to an unprotected zip file:</p>
 * <pre>
 *  ZipDecryptInputStream src = new ZipDecryptInputStream(new FileInputStream(srcFile), password);
 *  FileOutputStream dest = new FileOutputStream(destFile);
 *
 *  // should wrap with try-catch-finally, do the close in finally
 *  int b;
 *  while ((b = src.read()) > -1) {
 *      dest.write(b);
 *  }
 *
 *  src.close();
 *  dest.close();
 * </pre>
 *
 * @author Martin Matula (martin at alutam.com)
 */
public class ZipDecryptInputStream extends InputStream {
    private final InputStream delegate;
    private final int keys[] = new int[3];
    private final int pwdKeys[] = new int[3];

    private State state = State.SIGNATURE;
    private Section section;
    private int skipBytes;
    private int compressedSize;
    private int crc;

    /**
     * Creates a new instance of the stream.
     *
     * @param stream Input stream serving the password-protected zip file to be decrypted.
     * @param password Password to be used to decrypt the password-protected zip file.
     */
    public ZipDecryptInputStream(InputStream stream, String password) {
        this(stream, password.toCharArray());
    }

    /**
     * Safer constructor. Takes password as a char array that can be nulled right after
     * calling this constructor instead of a string that may be visible on the heap for
     * the duration of application run time.
     *
     * @param stream Input stream serving the password-protected zip file.
     * @param password Password to use for decrypting the zip file.
     */
    public ZipDecryptInputStream(InputStream stream, char[] password) {
        this.delegate = stream;
        pwdKeys[0] = 305419896;
        pwdKeys[1] = 591751049;
        pwdKeys[2] = 878082192;
        for (int i = 0; i < password.length; i++) {
            ZipUtil.updateKeys((byte) (password[i] & 0xff), pwdKeys);
        }
    }

    @Override
    public int read() throws IOException {
        int result = delegateRead();
        if (skipBytes == 0) {
            switch (state) {
                case SIGNATURE:
                    if (!peekAheadEquals(LFH_SIGNATURE)) {
                        state = State.TAIL;
                    } else {
                        section = Section.FILE_HEADER;
                        skipBytes = 5;
                        state = State.FLAGS;
                    }
                    break;
                case FLAGS:
                    if ((result & 1) == 0) {
                        throw new IllegalStateException("ZIP not password protected.");
                    }
                    if ((result & 64) == 64) {
                        throw new IllegalStateException("Strong encryption used.");
                    }
                    if ((result & 8) == 8) {
                        compressedSize = -1;
                        state = State.FN_LENGTH;
                        skipBytes = 19;
                    } else {
                        state = State.CRC;
                        skipBytes = 10;
                    }
                    result -= 1;
                    break;
                case CRC:
                    crc = result;
                    state = State.COMPRESSED_SIZE;
                    break;
                case COMPRESSED_SIZE:
                    int[] values = new int[4];
                    peekAhead(values);
                    compressedSize = 0;
                    int valueInc = DECRYPT_HEADER_SIZE;
                    for (int i = 0; i < 4; i++) {
                        compressedSize += values[i] << (8 * i);
                        values[i] -= valueInc;
                        if (values[i] < 0) {
                            valueInc = 1;
                            values[i] += 256;
                        } else {
                            valueInc = 0;
                        }
                    }
                    overrideBuffer(values);
                    result = values[0];
                    if (section == Section.DATA_DESCRIPTOR) {
                        state = State.SIGNATURE;
                    } else {
                        state = State.FN_LENGTH;
                    }
                    skipBytes = 7;
                    break;
                case FN_LENGTH:
                    values = new int[4];
                    peekAhead(values);
                    skipBytes = 3 + values[0] + values[2] + (values[1] + values[3]) * 256;
                    state = State.HEADER;
                    break;
                case HEADER:
                    section = Section.FILE_DATA;
                    initKeys();
                    byte lastValue = 0;
                    for (int i = 0; i < DECRYPT_HEADER_SIZE; i++) {
                        lastValue = (byte) (result ^ decryptByte());
                        updateKeys(lastValue);
                        result = delegateRead();
                    }
                    if ((lastValue & 0xff) != crc) {
//                        throw new IllegalStateException("Wrong password!");
                    }
                    compressedSize -= DECRYPT_HEADER_SIZE;
                    state = State.DATA;
                    // intentionally no break
                case DATA:
                    if (compressedSize == -1 && peekAheadEquals(DD_SIGNATURE)) {
                        section = Section.DATA_DESCRIPTOR;
                        skipBytes = 5;
                        state = State.CRC;
                    } else {
                        result = (result ^ decryptByte()) & 0xff;
                        updateKeys((byte) result);
                        compressedSize--;
                        if (compressedSize == 0) {
                            state = State.SIGNATURE;
                        }
                    }
                    break;
                case TAIL:
                    // do nothing
            }
        } else {
            skipBytes--;
        }
        return result;
    }

    private static final int BUF_SIZE = 8;
    private int bufOffset = BUF_SIZE;
    private final int[] buf = new int[BUF_SIZE];

    private int delegateRead() throws IOException {
        bufOffset++;
        if (bufOffset >= BUF_SIZE) {
            fetchData(0);
            bufOffset = 0;
        }
        return buf[bufOffset];
    }

    private boolean peekAheadEquals(int[] values) throws IOException {
        prepareBuffer(values);
        for (int i = 0; i < values.length; i++) {
            if (buf[bufOffset + i] != values[i]) {
                return false;
            }
        }
        return true;
    }

    private void prepareBuffer(int[] values) throws IOException {
        if (values.length > (BUF_SIZE - bufOffset)) {
            for (int i = bufOffset; i < BUF_SIZE; i++) {
                buf[i - bufOffset] = buf[i];
            }
            fetchData(BUF_SIZE - bufOffset);
            bufOffset = 0;
        }
    }

    private void peekAhead(int[] values) throws IOException {
        prepareBuffer(values);
        System.arraycopy(buf, bufOffset, values, 0, values.length);
    }

    private void overrideBuffer(int[] values) throws IOException {
        prepareBuffer(values);
        System.arraycopy(values, 0, buf, bufOffset, values.length);
    }

    private void fetchData(int offset) throws IOException {
        for (int i = offset; i < BUF_SIZE; i++) {
            buf[i] = delegate.read();
            if (buf[i] == -1) {
                break;
            }
        }
    }

    @Override
    public void close() throws IOException {
        delegate.close();
        super.close();
    }

    private void initKeys() {
        System.arraycopy(pwdKeys, 0, keys, 0, keys.length);
    }

    private void updateKeys(byte charAt) {
        ZipUtil.updateKeys(charAt, keys);
    }

    private byte decryptByte() {
        int temp = keys[2] | 2;
        return (byte) ((temp * (temp ^ 1)) >>> 8);
    }
}