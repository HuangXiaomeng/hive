/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.hive.common.io.crypto;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.hadoop.util.ReflectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A common interface for a cryptographic algorithm.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public abstract class CryptoCodec {
  public static Logger LOG = LoggerFactory.getLogger(CryptoCodec.class);

  /**
   * Get crypto codec for specified algorithm/mode/padding.
   * 
   * @param conf
   *          the configuration
   * @param CipherSuite
   *          algorithm/mode/padding
   * @return CryptoCodec the codec object. Null value will be returned if no
   *         crypto codec classes with cipher suite configured.
   */
  public static CryptoCodec getInstance(Configuration conf, 
      CipherSuite cipherSuite) {
    Class<? extends CryptoCodec> clazz = getCodecClass(conf, cipherSuite);
    if (clazz == null) {
      return null;
    }
    CryptoCodec codec = null;
    try {
      CryptoCodec c = ReflectionUtils.newInstance(clazz, conf);
      if (c.getCipherSuite().getName().equals(cipherSuite.getName())) {
        if (codec == null) {
          LOG.debug("Using crypto codec {}.", clazz.getName());
          codec = c;
        }
      } else {
        LOG.warn("Crypto codec {} doesn't meet the cipher suite {}.", 
            clazz.getName(), cipherSuite.getName());
      }
    } catch (Exception e) {
      LOG.warn("Crypto codec {} is not available.", clazz.getName());
    }
    
    if (codec != null) {
      return codec;
    }
    
    throw new RuntimeException("No available crypto codec which meets " + 
        "the cipher suite " + cipherSuite.getName() + ".");
  }
  
  /**
   * Get crypto codec for algorithm/mode/padding in config value
   * hive.security.crypto.cipher.suite
   * 
   * @param conf
   *          the configuration
   * @return CryptoCodec the codec object Null value will be returned if no
   *         crypto codec classes with cipher suite configured.
   */
  public static CryptoCodec getInstance(Configuration conf) {
    String name = conf.get(ConfVars.HIVE_SECURITY_CRYPTO_CIPHER_SUITE.varname, 
        ConfVars.HIVE_SECURITY_CRYPTO_CIPHER_SUITE.getDefaultValue());
    return getInstance(conf, CipherSuite.convert(name));
  }
  
  private static Class<? extends CryptoCodec> getCodecClass(
      Configuration conf, CipherSuite cipherSuite) {
    Class<? extends CryptoCodec> result = null;
    String codecString = conf.get(ConfVars.HIVE_SECURITY_CRYPTO_CODEC.varname,
        ConfVars.HIVE_SECURITY_CRYPTO_CODEC.getDefaultValue());
    
    try {
      result = (Class<? extends CryptoCodec>) conf.getClassByName(codecString);
    } catch (ClassCastException e) {
      LOG.warn("Class " + codecString + " is not a CryptoCodec.");
    } catch (ClassNotFoundException e) {
      LOG.warn("Crypto codec " + codecString + " not found.");
    }
    
    return result;
  }

  /**
   * @return the CipherSuite for this codec.
   */
  public abstract CipherSuite getCipherSuite();

  /**
   * Return this codec's algorithm
   */
  public abstract String getAlgorithm();

  /**
   * Return the key length required by this cipher, in bytes
   */
  public abstract int getKeyLength();

  /**
   * Return the expected initialization vector length, in bytes, or 0 if not applicable
   */
  public abstract int getIvLength();

  /**
   * Get an encryptor for encrypting data.
   */
  public abstract Encryptor createEncryptor();

  /**
   * Return a decryptor for decrypting data.
   */
  public abstract Decryptor createDecryptor();

}
