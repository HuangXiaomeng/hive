/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hive.serde2.crypto;

import org.apache.hadoop.crypto.key.KeyProviderFactory;

public class CryptoConstants {
  // The length of key
  public static final int KEY_LENGTH = 128;

  // The length of IV
  public static final int IV_LENGTH = 128;

  // The keynames of every encrypted column split by ',', it should be set as TBLPROPERTIES
  // like TBLPROPERTIES('hive.encrypt.keynames'='hive.k1,hive.k2')
  public static final String HIVE_ENCRYPT_KEYNAMES = "hive.encrypt.keynames";

  // The iv of encrypted column, it generated randomly by IV_LENGTH and stored to TBLPROPERTIES
  public static final String HIVE_ENCRYPT_IV = "hive.encrypt.iv";

  // The format of kms_uri should like "kms://http@localhost:16000/kms"
  public static final String KMS_URI = KeyProviderFactory.KEY_PROVIDER_PATH;
}
