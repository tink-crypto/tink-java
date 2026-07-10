// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import static com.google.crypto.tink.internal.Util.UTF_8;

import com.google.errorprone.annotations.InlineMe;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Functions to parse and serialize Keyset in Tink's JSON format based on Protobufs. */
public final class TinkJsonProtoKeysetFormat {

  /**
   * Parses a keyset in Tink's JSON format based on Protobufs, using the {@link
   * RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, RegistryConfiguration.get(),"
              + " access)",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeyset(String serializedKeyset, SecretKeyAccess access)
      throws GeneralSecurityException {
    return parseKeyset(serializedKeyset, RegistryConfiguration.get(), access);
  }

  /**
   * Parses a keyset in Tink's JSON format based on Protobufs, using the provided {@link
   * Configuration}.
   */
  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeyset(
      String serializedKeyset, Configuration configuration, SecretKeyAccess access)
      throws GeneralSecurityException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    try {
      return KeysetHandle.fromKeyset(
          JsonKeysetReader.withString(serializedKeyset).read(), configuration);
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  /**
   * Serializes a keyset in Tink's JSON format based on Protobufs, using the {@link
   * RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, RegistryConfiguration.get(),"
              + " access)",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  @SuppressWarnings("UnusedException")
  public static String serializeKeyset(KeysetHandle keysetHandle, SecretKeyAccess access)
      throws GeneralSecurityException {
    return serializeKeyset(keysetHandle, RegistryConfiguration.get(), access);
  }

  /**
   * Serializes a keyset in Tink's JSON format based on Protobufs, using the provided {@link
   * Configuration}.
   */
  @SuppressWarnings({"UnusedException", "deprecation"})
  public static String serializeKeyset(
      KeysetHandle keysetHandle, Configuration configuration, SecretKeyAccess access)
      throws GeneralSecurityException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      JsonKeysetWriter.withOutputStream(outputStream).write(keysetHandle.getKeyset(configuration));
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  /**
   * Parses a keyset without secret key material in Tink's JSON format based on Protobufs, using the
   * {@link RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset,"
              + " RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeysetWithoutSecret(String serializedKeyset)
      throws GeneralSecurityException {
    return parseKeysetWithoutSecret(serializedKeyset, RegistryConfiguration.get());
  }

  /**
   * Parses a keyset without secret key material in Tink's JSON format based on Protobufs, using the
   * provided {@link Configuration}.
   */
  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeysetWithoutSecret(
      String serializedKeyset, Configuration configuration) throws GeneralSecurityException {
    try {
      KeysetReader reader = JsonKeysetReader.withString(serializedKeyset);
      byte[] serializedKeysetBytes = reader.read().toByteArray();
      return KeysetHandle.readNoSecret(serializedKeysetBytes, configuration);
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  /**
   * Serializes a keyset without secret key material in Tink's JSON format based on Protobufs, using
   * the {@link RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle,"
              + " RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  @SuppressWarnings("UnusedException")
  public static String serializeKeysetWithoutSecret(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return serializeKeysetWithoutSecret(keysetHandle, RegistryConfiguration.get());
  }

  /**
   * Serializes a keyset without secret key material in Tink's JSON format based on Protobufs, using
   * the provided {@link Configuration}.
   */
  @SuppressWarnings({"UnusedException", "deprecation"})
  public static String serializeKeysetWithoutSecret(
      KeysetHandle keysetHandle, Configuration configuration) throws GeneralSecurityException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      keysetHandle.writeNoSecret(JsonKeysetWriter.withOutputStream(outputStream), configuration);
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  /**
   * Parses an encrypted keyset in Tink's JSON format based on Protobufs, using the {@link
   * RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.parseEncryptedKeyset(serializedEncryptedKeyset,"
              + " keysetEncryptionAead, associatedData, RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  public static KeysetHandle parseEncryptedKeyset(
      String serializedEncryptedKeyset, Aead keysetEncryptionAead, byte[] associatedData)
      throws GeneralSecurityException {
    return parseEncryptedKeyset(
        serializedEncryptedKeyset,
        keysetEncryptionAead,
        associatedData,
        RegistryConfiguration.get());
  }

  /**
   * Parses an encrypted keyset in Tink's JSON format based on Protobufs, using the provided {@link
   * Configuration}.
   */
  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseEncryptedKeyset(
      String serializedEncryptedKeyset,
      Aead keysetEncryptionAead,
      byte[] associatedData,
      Configuration configuration)
      throws GeneralSecurityException {
    try {
      return KeysetHandle.readWithAssociatedData(
          JsonKeysetReader.withString(serializedEncryptedKeyset),
          keysetEncryptionAead,
          associatedData,
          configuration);
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  /**
   * Serializes an encrypted keyset in Tink's JSON format based on Protobufs, using the {@link
   * RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, keysetEncryptionAead,"
              + " associatedData, RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkJsonProtoKeysetFormat"
      })
  @Deprecated // This function should be inlined.
  public static String serializeEncryptedKeyset(
      KeysetHandle keysetHandle, Aead keysetEncryptionAead, byte[] associatedData)
      throws GeneralSecurityException {
    return serializeEncryptedKeyset(
        keysetHandle, keysetEncryptionAead, associatedData, RegistryConfiguration.get());
  }

  /**
   * Serializes an encrypted keyset in Tink's JSON format based on Protobufs, using the provided
   * {@link Configuration}.
   */
  @SuppressWarnings("UnusedException")
  public static String serializeEncryptedKeyset(
      KeysetHandle keysetHandle,
      Aead keysetEncryptionAead,
      byte[] associatedData,
      Configuration configuration)
      throws GeneralSecurityException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      keysetHandle.writeWithAssociatedData(
          JsonKeysetWriter.withOutputStream(outputStream),
          keysetEncryptionAead,
          associatedData,
          configuration);
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  private TinkJsonProtoKeysetFormat() {}
}
