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

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.hive.common.io.crypto.Encryptor;
import org.apache.hadoop.hive.common.io.crypto.Key;

import com.google.common.base.Preconditions;

@InterfaceAudience.Private
@InterfaceStability.Evolving
public class AesEncryptor extends Encryptor {

  private final Cipher cipher;
  private final SecureRandom rng;
  private Key key;
  private byte[] iv;
  private boolean initialized = false;

  public AesEncryptor(Cipher cipher, SecureRandom rng) {
    this.cipher = cipher;
    this.rng = rng;
  }

  public AesEncryptor(Cipher cipher, SecureRandom rng, Key key, byte[] iv) {
    this.cipher = cipher;
    this.rng = rng;
    this.key = key;
    this.iv = Arrays.copyOf(iv, iv.length);
  }

  public Cipher getCipher() {
    return cipher;
  }

  @Override
  public Key getKey() {
    return key;
  }

  @Override
  public void setKey(Key key) {
    Preconditions.checkNotNull(key, "Key cannot be null");
    if (key != null) {
      Preconditions.checkArgument(key.getMaterial().length == JceAesCtrCryptoCodec.KEY_LENGTH,
          "Invalid key length");
    }
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
    this.iv = Arrays.copyOf(iv, iv.length);
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
