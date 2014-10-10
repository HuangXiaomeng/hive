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
package org.apache.hadoop.hive.common.crypto;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configurable;

/**
 * A generic interface for a cryptographic codec.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public interface CryptoCodec extends Configurable {

  /**
   * Return the CipherSuite for this codec.
   */
  public CipherSuite getCipherSuite();

  /**
   * Return this codec's algorithm.
   */
  public String getAlgorithm();

  /**
   * Return the key length required by this cipher, in bytes.
   */
  public int getKeyLength();

  /**
   * Return the expected initialization vector length, in bytes.
   */
  public int getIvLength();

  /**
   * Get an encryptor for encrypting data.
   */
  public Encryptor createEncryptor();

  /**
   * Return a decryptor for decrypting data.
   */
  public Decryptor createDecryptor();

}
