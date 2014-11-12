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
package org.apache.hadoop.hive.common.crypto.key;

import java.io.IOException;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

/**
 * KeyProvider is a interface to management secret
 * {@link org.apache.hadoop.hive.common.crypto.key.Key}
 * from key storage such as Java key store.
 *
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public interface KeyProvider {

  public static final String PASSWORD = "password";
  public static final String PASSWORDFILE = "passwordfile";

  /**
   * Initialize the key provider
   * @param params
   */
  public void init(String params);

  /**
   * Get the key for a given key name.
   * @param name, key name
   * @return the specific key corresponding to the supplied key name,
   * or null if the key is not found
   * @throws IOException
   */
  public Key getKey(String name) throws IOException;

  /**
   * Get keys for a given set of key names.
   * @param names, an array of key names
   * @return an array of keys corresponding to the supplied key names,
   * or null if none is found
   * @throws IOException
   */
  public Key[] getKeys(String[] names) throws IOException;

  /**
   * Create a new key. The given key must not already exist.
   * @param name, key name
   * @param material, the key material for the key.
   * @param cipher, the key cipher name.
   * @return the new key.
   * @throws IOException
   */
  public Key createKey(String name, byte[] material, String cipher) throws IOException;

  /**
   * Delete a key for a given key name.
   * @param name, key name
   * @throws IOException
   */
  public void deleteKey(String name) throws IOException;

}
