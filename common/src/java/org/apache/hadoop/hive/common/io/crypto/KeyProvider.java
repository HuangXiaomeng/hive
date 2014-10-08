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

/**
 * KeyProvider is a interface to abstract the different methods of retrieving
 * key material from key storage such as Java key store.
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
   * Retrieve the key for a given key name
   * @param keyName
   * @return the keys corresponding to the supplied alias, or null if a key is
   * not found
   */
  public Key getKey(String keyName);

  /**
   * Retrieve keys for a given set of key names
   * @param keyNames, an array of key names
   * @return an array of keys corresponding to the supplied aliases, an
   * entry will be null if a key is not found
   */
  public Key[] getKeys(String[] keyNames);

}
