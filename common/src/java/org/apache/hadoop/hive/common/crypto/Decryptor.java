/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hive.common.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

/**
 * Decryptors apply a cipher to an InputStream to recover plaintext.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public abstract class Decryptor {

  /**
   * Get the key
   */
  public abstract Key getKey();

  /**
   * Set the key
   * @param key
   */
  public abstract void setKey(Key key);

  /**
   * Get the expected length for the initialization vector
   * @return the expected length for the initialization vector
   */
  public abstract int getIvLength();

  /**
   * Get the cipher's internal block size
   * @return the cipher's internal block size
   */
  public abstract int getBlockSize();

  /**
   * Set the initialization vector
   * @param iv
   */
  public abstract void setIv(byte[] iv);

  /**
   * Reset state, reinitialize with the key and iv
   */
  public abstract void reset();

  /**
   * Create a stream for decryption
   * @param in
   */
  public abstract InputStream createDecryptionStream(InputStream in);

  /**
   * Decrypt a stream of ciphertext
   * @param in
   * @param out
   */
  public void decrypt(InputStream in, OutputStream out, int outLen)
      throws IOException {
    InputStream is = createDecryptionStream(in);
    byte buf[] = new byte[8*1024];
    long remaining = outLen;
    try {
      while (remaining > 0) {
        int toRead = (int)(remaining < buf.length ? remaining : buf.length);
        int read = is.read(buf, 0, toRead);
        if (read < 0) {
          break;
        }
        out.write(buf, 0, read);
        remaining -= read;
      }
    } finally {
      is.close();
    }
  }

  /**
   * Decrypt a stream to a array of byte
   * @param in
   * @param out
   */
  public void decrypt(InputStream in, byte[] dest, int destOffset,
      int destSize) throws IOException {
    InputStream is = createDecryptionStream(in);
    try {
      IOUtils.readFully(is, dest, destOffset, destSize);
    } finally {
      is.close();
    }
  }
}
