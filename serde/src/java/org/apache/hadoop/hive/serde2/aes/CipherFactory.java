package org.apache.hadoop.hive.serde2.aes;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class CipherFactory {
  
  /**
   * Create an instance of this Cipher class, according to the algorithm string
   * 
   * @param transformation
   * @return cipher instance
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws InstantiationException
   * @throws IllegalAccessException
   */
  public static Cipher getInstance(String transformation)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InstantiationException, IllegalAccessException {
    return getInstance(transformation, null);
  }
  
  /**
   * Create an instance of this Cipher class, according to the algorithm string
   * and provider.
   * 
   * @param transformation
   * @param provider
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws InstantiationException
   * @throws IllegalAccessException
   */
  public static Cipher getInstance(String transformation, String provider)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InstantiationException, IllegalAccessException {
    Cipher cipher = null;
    try {
      if (provider == null || provider.isEmpty()) {
        cipher = Cipher.getInstance(transformation);
      } else {
        cipher = Cipher.getInstance(transformation, provider);
      }
    } catch (NoSuchProviderException e) {
      cipher = Cipher.getInstance(transformation);
    }
    return cipher;
  }
}
