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
package org.apache.hadoop.hive.common.crypto.aes;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.common.crypto.CipherSuite;
import org.apache.hadoop.hive.common.crypto.CryptoCodec;
import org.apache.hadoop.hive.common.crypto.Decryptor;
import org.apache.hadoop.hive.common.crypto.Encryptor;

import com.google.common.annotations.VisibleForTesting;

/**
 * Abstract class implements AES crypto codec using JCE provider.
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
public abstract class JceAesCryptoCodec implements CryptoCodec {
  private static final Log LOG = LogFactory.getLog(JceAesCtrCryptoCodec.class);

  public static final int KEY_LENGTH = 16;
  public static final int KEY_LENGTH_BITS = KEY_LENGTH * 8;
  public static final int BLOCK_SIZE = 16;
  public static final int IV_LENGTH = 16;
  public static final String ALGORITHM = "AES";

  public static final String CIPHER_PROVIDER_KEY = "hive.security.crypto.jce.provider";
  public static final String RNG_ALGORITHM_KEY = "hive.security.crypto.rng.algorithm";
  public static final String RNG_PROVIDER_KEY = "hive.security.crypto.rng.provider";

  private Configuration conf;
  private String rngAlgorithm;
  protected String cipherProvider;
  private SecureRandom rng;

  @Override
  public Configuration getConf() {
    return conf;
  }

  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
    // The JCE provider, null if default
    cipherProvider = conf.get(CIPHER_PROVIDER_KEY);
    // RNG algorithm
    rngAlgorithm = conf.get(RNG_ALGORITHM_KEY, "SHA1PRNG");
    // RNG provider, null if default
    String rngProvider = conf.get(RNG_PROVIDER_KEY);
    try {
      if (rngProvider != null) {
        rng = SecureRandom.getInstance(rngAlgorithm, rngProvider);
      } else {
        rng = SecureRandom.getInstance(rngAlgorithm);
      }
    } catch (GeneralSecurityException e) {
      LOG.warn("Could not instantiate specified RNG, falling back to default", e);
      rng = new SecureRandom();
    }
  }

  /**
   * Return the CipherSuite for this codec.
   */
  @Override
  public abstract CipherSuite getCipherSuite();

  @Override
  public String getAlgorithm() {
    return ALGORITHM;
  }

  @Override
  public int getKeyLength() {
    return KEY_LENGTH;
  }

  @Override
  public int getIvLength() {
    return IV_LENGTH;
  }

  @Override
  public Encryptor createEncryptor() {
    return new AesEncryptor(getJCECipherInstance(), rng);
  }

  @Override
  public Decryptor createDecryptor() {
    return new AesDecryptor(getJCECipherInstance());
  }

  @VisibleForTesting
  SecureRandom getRNG() {
    return rng;
  }

  /**
   * Return the Jce cipher instance for this codec.
   */
  protected abstract javax.crypto.Cipher getJCECipherInstance();
}
