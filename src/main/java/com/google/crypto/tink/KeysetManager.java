// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter;
import com.google.crypto.tink.internal.ProtoConversions;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.InlineMe;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;

/**
 * Manages a {@link Keyset} proto, with convenience methods that rotate, disable, enable or destroy
 * keys.
 *
 * <p>We do not recommend usage of this class. Instead, we recommend you to use a {@link
 * Keyset.Builder} which has an improved API (in that it e.g. returns the just added objects,
 * allowing you to manipulate them further).
 *
 * @since 1.0.0
 */
public final class KeysetManager {
  @GuardedBy("this")
  private final Keyset.Builder keysetBuilder;

  private final Configuration configuration;

  private KeysetManager(Keyset.Builder val, Configuration configuration) {
    keysetBuilder = val;
    this.configuration = configuration;
  }

  /**
   * Returns a KeysetManager with the same keyset as the given {code val}.
   *
   * <p>Note that the KeysetManager APIs mix proto-serialized and non-serialized keys, Because of
   * this, we recommend {@code KeysetHandle.Builder} instead. However, for legacy code {@code
   * KeysetManager} can be useful. In order to convert back and forth from the serialized and
   * non-serialized form we use the given {@code Configuration}.
   *
   * @return a {@link KeysetManager} for the keyset managed by {@code val}
   * @throws GeneralSecurityException if {@code val} contains keys that cannot be serialized into
   *     the Tink proto format (for example, custom {@link Key} subclasses without a registered
   *     serializer in {@code configuration}).
   */
  public static KeysetManager withKeysetHandle(KeysetHandle val, Configuration configuration)
      throws GeneralSecurityException {
    return new KeysetManager(val.getKeyset(configuration).toBuilder(), configuration);
  }

  /**
   * Returns a KeysetManager with the same keyset as the given {code val}.
   *
   * <p>This should not be used, instead use the overload which also takes a {@code Configuration}.
   * For full compatibility, pass in {@code RegistryConfiguration.get()}.
   *
   * @return a {@link KeysetManager} for the keyset manged by {@code val}
   * @throws IllegalArgumentException if {@code val} contains keys that cannot be serialized into
   *     the Tink proto format (for example, custom {@link Key} subclasses without a registered
   *     serializer).
   * @deprecated This function should be inlined.
   */
  @Deprecated // This function should be inlined.
  public static KeysetManager withKeysetHandle(KeysetHandle val) {
    try {
      return withKeysetHandle(val, RegistryConfiguration.get());
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException(
          "Cannot create KeysetManager: key cannot be serialized", e);
    }
  }

  /** @return a {@link KeysetManager} for an empty keyset. */
  public static KeysetManager withEmptyKeyset(Configuration configuration) {
    return new KeysetManager(Keyset.newBuilder(), configuration);
  }

  /**
   * @return a {@link KeysetManager} for an empty keyset.
   * @deprecated This function should be inlined.
   */
  @Deprecated // This function should be inlined.
  public static KeysetManager withEmptyKeyset() {
    try {
      return withEmptyKeyset(RegistryConfiguration.get());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** @return a {@link KeysetHandle} of the managed keyset */
  public synchronized KeysetHandle getKeysetHandle() throws GeneralSecurityException {
    return KeysetHandle.fromKeyset(keysetBuilder.build(), configuration);
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}, and sets the new key as the
   * primary key.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager rotate(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    addNewKey(keyTemplate, true);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager add(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    addNewKey(keyTemplate, false);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager add(KeyTemplate keyTemplate) throws GeneralSecurityException {
    Keyset.Key key = newKey(keyTemplate.toParameters());
    keysetBuilder.addKey(key);
    return this;
  }

  /**
   * Adds the input {@link KeyHandle} to the existing keyset. The KeyStatusType and key ID of the
   * {@link KeyHandle} are used as-is in the keyset.
   *
   * @throws UnsupportedOperationException if the {@link KeyHandle} contains a {@link TinkKey} which
   *     is not a {@link ProtoKey}.
   * @throws GeneralSecurityException if the {@link KeyHandle}'s key ID collides with another key ID
   *     in the keyset.
   * @deprecated We recommend to use the {@code KeysetHandle.Builder} API.
   */
  @CanIgnoreReturnValue
  @Deprecated
  public synchronized KeysetManager add(KeyHandle keyHandle)
      throws GeneralSecurityException {
    ProtoKey pkey;
    try {
      pkey = (ProtoKey) keyHandle.getKey(SecretKeyAccess.insecureSecretAccess());
    } catch (ClassCastException e) {
      throw new UnsupportedOperationException(
          "KeyHandles which contain TinkKeys that are not ProtoKeys are not yet supported.", e);
    }

    if (keyIdExists(keyHandle.getId())) {
      throw new GeneralSecurityException(
          "Trying to add a key with an ID already contained in the keyset.");
    }

    keysetBuilder.addKey(
        Keyset.Key.newBuilder()
            .setKeyData(pkey.getProtoKey())
            .setKeyId(keyHandle.getId())
            .setStatus(KeyStatusTypeProtoConverter.toProto(keyHandle.getStatus()))
            .setOutputPrefixType(KeyTemplate.toProto(pkey.getOutputPrefixType()))
            .build());
    return this;
  }

  /**
   * Adds the input {@code KeyHandle} to the existing keyset with {@code OutputPrefixType.TINK}.
   *
   * @throws GeneralSecurityException if the given {@code KeyAccess} does not grant access to the
   *     key contained in the {@code KeyHandle}.
   * @throws UnsupportedOperationException if the {@code KeyHandle} contains a {@code TinkKey} which
   *     is not a {@code ProtoKey}.
   * @deprecated We recommend to use the {@code KeysetHandle.Builder} API.
   */
  @CanIgnoreReturnValue
  @Deprecated
  public synchronized KeysetManager add(KeyHandle keyHandle, KeyAccess access)
      throws GeneralSecurityException {
    return add(keyHandle);
  }

  /**
   * Generates a fresh key using {@code keyTemplate} and returns the {@code keyId} of it. In case
   * {@code asPrimary} is true the generated key will be the new primary.
   */
  @CanIgnoreReturnValue
  public synchronized int addNewKey(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate, boolean asPrimary)
      throws GeneralSecurityException {
    Keyset.Key key =
        newKey(TinkProtoParametersFormat.parse(keyTemplate.toByteArray(), configuration));
    keysetBuilder.addKey(key);
    if (asPrimary) {
      keysetBuilder.setPrimaryKeyId(key.getKeyId());
    }
    return key.getKeyId();
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager setPrimary(int keyId) throws GeneralSecurityException {
    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (!key.getStatus().equals(KeyStatusType.ENABLED)) {
          throw new GeneralSecurityException(
              "cannot set key as primary because it's not enabled: " + keyId);
        }
        keysetBuilder.setPrimaryKeyId(keyId);
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   */
  @InlineMe(replacement = "this.setPrimary(keyId)")
  @CanIgnoreReturnValue
  public synchronized KeysetManager promote(int keyId) throws GeneralSecurityException {
    return setPrimary(keyId);
  }

  /**
   * Enables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager enable(int keyId) throws GeneralSecurityException {
    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException("cannot enable key with id " + keyId);
        }
        keysetBuilder.setKey(i, key.toBuilder().setStatus(KeyStatusType.ENABLED).build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Disables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager disable(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot disable the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException("cannot disable key with id " + keyId);
        }
        keysetBuilder.setKey(i, key.toBuilder().setStatus(KeyStatusType.DISABLED).build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Deletes the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager delete(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot delete the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        keysetBuilder.removeKey(i);
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Destroys the key material associated with the {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  @CanIgnoreReturnValue
  public synchronized KeysetManager destroy(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot destroy the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED
            && key.getStatus() != KeyStatusType.DISABLED
            && key.getStatus() != KeyStatusType.DESTROYED) {
          throw new GeneralSecurityException("cannot destroy key with id " + keyId);
        }
        keysetBuilder.setKey(
            i, key.toBuilder().setStatus(KeyStatusType.DESTROYED).clearKeyData().build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  @AccessesPartialKey
  @LowLevelCryptoCaller
  private synchronized Keyset.Key newKey(Parameters parameters) throws GeneralSecurityException {
    @Nullable ProtoKeySerializer serializer = configuration.getOrNull(ProtoKeySerializer.class);
    if (serializer == null) {
      throw new GeneralSecurityException(
          "Cannot create key: configuration does not support ProtoKeySerializer.");
    }
    int keyId = newKeyId();
    Integer idRequirement = parameters.hasIdRequirement() ? keyId : null;
    Key key = configuration.createKey(parameters, idRequirement);
    ProtoKeySerialization serializedKey =
        serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(serializedKey.getTypeUrl())
            .setValue(serializedKey.getValue())
            .setKeyMaterialType(ProtoConversions.toProto(serializedKey.getKeyMaterialType()))
            .build();
    return createKeysetKey(
        keyData, ProtoConversions.toProto(serializedKey.getOutputPrefixType()), keyId);
  }

  private synchronized Keyset.Key createKeysetKey(
      KeyData keyData, OutputPrefixType outputPrefixType, int keyId)
      throws GeneralSecurityException {
    if (outputPrefixType == OutputPrefixType.UNKNOWN_PREFIX) {
      throw new GeneralSecurityException("unknown output prefix type");
    }
    return Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(outputPrefixType)
        .build();
  }

  private synchronized boolean keyIdExists(int keyId) {
    for (Keyset.Key key : keysetBuilder.getKeyList()) {
      if (key.getKeyId() == keyId) {
        return true;
      }
    }
    return false;
  }

  private synchronized int newKeyId() {
    int keyId = Util.randKeyId();
    while (keyIdExists(keyId)) {
      keyId = Util.randKeyId();
    }
    return keyId;
  }
}
