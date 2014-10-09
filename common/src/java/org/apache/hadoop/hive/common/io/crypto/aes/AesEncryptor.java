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
package org.apache.hadoop.hive.common.io.crypto.aes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.hive.common.io.crypto.Encryptor;
import org.apache.hadoop.hive.common.io.crypto.Key;

import com.google.common.base.Preconditions;

@InterfaceAudience.Private
@InterfaceStability.Evolving
public class AesEncryptor implements Encryptor {

  private final javax.crypto.Cipher cipher;
  private final SecureRandom rng;
  private Key key;
  private byte[] iv;
  private boolean initialized = false;

  public AesEncryptor(javax.crypto.Cipher cipher, SecureRandom rng) {
    this.cipher = cipher;
    this.rng = rng;
  }

  javax.crypto.Cipher getCipher() {
    return cipher;
  }

  @Override
  public void setKey(Key key) {
    this.key = key;
  }

  @Override
  public int getIvLength() {
    return JceAesCtrCryptoCodec.IV_LENGTH;
  }

  @Override
  public int getBlockSize() {
    return JceAesCtrCryptoCodec.BLOCK_SIZE;
  }

  @Override
  public byte[] getIv() {
    return iv;
  }

  @Override
  public void setIv(byte[] iv) {
    if (iv != null) {
      Preconditions.checkArgument(iv.length == JceAesCtrCryptoCodec.IV_LENGTH,
          "Invalid IV length");
    }
    this.iv = iv;
  }

  @Override
  public void reset() {
    init();
  }

  @Override
  public OutputStream createEncryptionStream(OutputStream out) {
    if (!initialized) {
      init();
    }
    return new javax.crypto.CipherOutputStream(out, cipher);
  }

  @Override
  public void encrypt(InputStream in, OutputStream out) throws IOException {
    OutputStream os = createEncryptionStream(out);
    try {
      IOUtils.copy(in, os);
    } finally {
      os.close();
    }
  }

  @Override
  public void encrypt(byte[] src, int offset, int length,
      OutputStream out) throws IOException {
    OutputStream os = createEncryptionStream(out);
    try {
      os.write(src, offset, length);
    } finally {
      os.close();
    }
  }

  protected void init() {
    try {
      if (iv == null) {
        iv = new byte[getIvLength()];
        rng.nextBytes(iv);
      }
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
          new SecretKeySpec(key.getMaterial(), "AES"), new IvParameterSpec(iv));
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
    initialized = true;
  }
}
