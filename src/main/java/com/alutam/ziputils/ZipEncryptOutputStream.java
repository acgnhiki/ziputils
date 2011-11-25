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

import java.security.SecureRandom;
import java.io.IOException;
import java.io.OutputStream;
import static com.alutam.ziputils.ZipUtil.*;

/**
 *
 * @author martin
 */
public class ZipEncryptOutputStream extends OutputStream {
    private final OutputStream delegate;
    private final int keys[] = new int[3];
    private final int pwdKeys[] = new int[3];

    private int skipBytes;
    private State state = State.SIGNATURE;
    private State nextState;
    private int value;
    private int valuePos;
    private int valueInc;
    private byte[] dh;

    public ZipEncryptOutputStream(OutputStream delegate, String password) {
        this(delegate, password.toCharArray());
    }

    public ZipEncryptOutputStream(OutputStream delegate, char[] password) {
        this.delegate = delegate;
        pwdKeys[0] = 305419896;
        pwdKeys[1] = 591751049;
        pwdKeys[2] = 878082192;
        for (int i = 0; i < password.length; i++) {
            ZipUtil.updateKeys((byte) (password[i] & 0xff), pwdKeys);
        }
    }

    @Override
    public void write(int b) throws IOException {
        if (skipBytes == 0) {
            switch (state) {
                case SIGNATURE:
                    if (b != LFH_SIGNATURE[valuePos]) {
                        state = State.TAIL;
                    } else {
                        valuePos++;
                        if (valuePos >= LFH_SIGNATURE.length) {
                            skipBytes = 2;
                            state = State.FLAGS;
                        }
                    }
                    dh = null;
                    break;
                case FLAGS:
                    if ((b & 1) == 1) {
                        throw new IllegalStateException("ZIP already password protected.");
                    }
                    if ((b & 64) == 64) {
                        throw new IllegalStateException("Strong encryption used.");
                    }
                    if ((b & 8) == 0) {
                        throw new IllegalStateException("Unsupported ZIP format.");
                    }
                    b += 1;
                    valuePos = 0;
                    value = 0;
                    valueInc = DECRYPT_HEADER_SIZE;
                    skipBytes = 19;
//                    skipBytes = 9;
//                    state = State.CRC;
                    nextState = State.FN_LENGTH;
                    state = nextState;
                    break;
                case CRC:
                    if (dh == null) {
                        initKeys();
                        SecureRandom random = new SecureRandom();
                        dh = new byte[DECRYPT_HEADER_SIZE];
                        random.nextBytes(dh);
                    }
                    b = dh[dh.length - 2 + value] & 0xff;
//                    System.out.println("Writing CRC (index " + value + "): " + (dh[dh.length - 2 + value] & 0xff));
                    value++;
                    if (value > 1) {
                        value = 0;
                        skipBytes = (nextState == State.FN_LENGTH) ? 8 : 0;
                        state = nextState;
                    }
                    break;
                case COMPRESSED_SIZE:
                    b += valueInc;
                    if (b >= 256) {
                        valueInc = 1;
                        b -= 256;
                    } else {
                        valueInc = 0;
                    }
                    valuePos++;
                    if (valuePos > 3) {
                        valuePos = 0;
                        value = 0;
                        state = State.SIGNATURE;
                        skipBytes = 4;
                    }
                    break;
                case FN_LENGTH:
                case EF_LENGTH:
                    value += b << 8 * valuePos;
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
                    if (dh == null) {
                        initKeys();
                        SecureRandom random = new SecureRandom();
                        dh = new byte[DECRYPT_HEADER_SIZE];
                        random.nextBytes(dh);
                    }
                    for (int i = 0; i < DECRYPT_HEADER_SIZE; i++) {
                        delegate.write((dh[i] ^ encryptByte()) & 0xff);
                        updateKeys(dh[i]);
                    }
                    value = 0;
                    state = State.DATA;
                    // intentionally no break
                case DATA:
                    if (DD_SIGNATURE[value] == b) {
                        value++;
                        if (value == DD_SIGNATURE.length) {
                            // was a signature - write out and switch state
                            for (int i = 0; i < DD_SIGNATURE.length; i++) {
                                delegate.write(DD_SIGNATURE[i]);
                            }
                            value = 0;
                            valuePos = 0;
                            skipBytes = 2;
                            state = State.CRC;
                            nextState = State.COMPRESSED_SIZE;
                        }
                        return;
                    } else {
                        // was not the signature -> encrypt and write out
                        for (int i = 0; i < value; i++) {
                            delegate.write((DD_SIGNATURE[i] ^ encryptByte()) & 0xff);
                            updateKeys((byte) DD_SIGNATURE[i]);
                        }
                        value = 0;
                    }
                    int newB = (b ^ encryptByte()) & 0xff;
                    updateKeys((byte) b);
                    b = newB;
                    break;
                case TAIL:
                    // do nothing
            }
        } else {
            skipBytes--;
        }
        delegate.write(b);
    }

    @Override
    public void close() throws IOException {
        super.close();
        delegate.close();
    }

    private void initKeys() {
        System.arraycopy(pwdKeys, 0, keys, 0, keys.length);
    }

    private void updateKeys(byte charAt) {
        ZipUtil.updateKeys(charAt, keys);
    }

    private byte encryptByte() {
        int temp = keys[2] | 2;
        return (byte) ((temp * (temp ^ 1)) >>> 8);
    }
}
