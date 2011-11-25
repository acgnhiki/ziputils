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

import java.io.IOException;
import java.io.InputStream;
import static com.alutam.ziputils.ZipUtil.*;

public class ZipDecryptInputStream extends InputStream {
    private final InputStream delegate;
    private final int keys[] = new int[3];
    private final int pwdKeys[] = new int[3];

    private State state = State.SIGNATURE;
    private int skipBytes;
    private int compressedSize;
    private int value;
    private int valuePos;
    private int valueInc;
    private int crc;

    public ZipDecryptInputStream(InputStream stream, String password) {
        this(stream, password.toCharArray());
    }

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
        int result = delegate.read();
        if (skipBytes == 0) {
            switch (state) {
                case SIGNATURE:
                    if (result != LFH_SIGNATURE[valuePos]) {
                        state = State.TAIL;
                    } else {
                        valuePos++;
                        if (valuePos >= LFH_SIGNATURE.length) {
                            skipBytes = 2;
                            state = State.FLAGS;
                        }
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
                        throw new IllegalStateException("Unsupported ZIP format.");
                    }
                    result -= 1;
                    compressedSize = 0;
                    valuePos = 0;
                    valueInc = DECRYPT_HEADER_SIZE;
                    state = State.CRC;
                    skipBytes = 10;
                    break;
                case CRC:
                    crc = result;
                    state = State.COMPRESSED_SIZE;
                    break;
                case COMPRESSED_SIZE:
                    compressedSize += result << (8 * valuePos);
                    result -= valueInc;
                    if (result < 0) {
                        valueInc = 1;
                        result += 256;
                    } else {
                        valueInc = 0;
                    }
                    valuePos++;
                    if (valuePos > 3) {
                        valuePos = 0;
                        value = 0;
                        state = State.FN_LENGTH;
                        skipBytes = 4;
                    }
                    break;
                case FN_LENGTH:
                case EF_LENGTH:
                    value += result << 8 * valuePos;
                    if (valuePos == 1) {
                        valuePos = 0;
                        if (state == State.FN_LENGTH) {
                            state = State.EF_LENGTH;
                        } else {
                            state = State.HEADER;
                            skipBytes = value;
                        }
                    } else {
                        valuePos = 1;
                    }
                    break;
                case HEADER:
                    initKeys();
                    byte lastValue = 0;
                    for (int i = 0; i < DECRYPT_HEADER_SIZE; i++) {
                        lastValue = (byte) (result ^ decryptByte());
                        updateKeys(lastValue);
                        result = delegate.read();
                    }
                    if ((lastValue & 0xff) != crc) {
                        throw new IllegalStateException("Wrong password!");
                    }
                    compressedSize -= DECRYPT_HEADER_SIZE;
                    state = State.DATA;
                    // intentionally no break
                case DATA:
                    result = (result ^ decryptByte()) & 0xff;
                    updateKeys((byte) result);
                    compressedSize--;
                    if (compressedSize == 0) {
                        valuePos = 0;
                        state = State.SIGNATURE;
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