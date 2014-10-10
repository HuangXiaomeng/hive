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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encryptors apply a cipher to an OutputStream to produce ciphertext.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public abstract class Encryptor {
  public static Logger LOG = LoggerFactory.getLogger(Encryptor.class);

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
   * Get the initialization vector
   */
  public abstract byte[] getIv();

  /**
   * Set the initialization vector
   * @param iv
   */
  public abstract void setIv(byte[] iv);

  /**
   * Reset state, reinitialize with the key and iv
   */
  public abstract void  reset();

  /**
   * Create a stream for encryption
   * @param out
   */
  public abstract OutputStream createEncryptionStream(OutputStream out);

  /**
   * Encrypt a stream of plaintext
   * @param in
   * @param out
   */
  public void encrypt(InputStream in, OutputStream out) throws IOException {
    OutputStream os = createEncryptionStream(out);
    try {
      IOUtils.copy(in, os);
    } finally {
      os.close();
    }
  }

  /**
   * Encrypt a array of byte of plaintext
   * @param src
   * @param offset
   * @param length
   * @param out
   */
  public void encrypt(byte[] src, int offset, int length,
      OutputStream out) throws IOException {
    OutputStream os = createEncryptionStream(out);
    try {
      os.write(src, offset, length);
    } finally {
      os.close();
    }
  }
}
