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

/**
 * Key is class contains key name and key material.
 *
 */
public class Key {
  private final String name;
  private final byte[] material;

  protected Key(String name, byte[] material) {
    this.name = name;
    this.material = material;
  }

  public String getName() {
    return name;
  }

  public byte[] getMaterial() {
    return material;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    buf.append("key");
    buf.append("=");
    if (material == null) {
      buf.append("null");
    } else {
      for(byte b: material) {
        buf.append(' ');
        int right = b & 0xff;
        if (right < 0x10) {
          buf.append('0');
        }
        buf.append(Integer.toHexString(right));
      }
    }
    return buf.toString();
  }
}
