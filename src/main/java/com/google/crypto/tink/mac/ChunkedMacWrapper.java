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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * ChunkedMacWrapper is the implementation of PrimitiveWrapper for the ChunkedMac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To compute a MAC tag,
 * it uses the primary key in the keyset, and prepends to the tag a certain prefix associated with
 * the primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select
 * the right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class ChunkedMacWrapper implements PrimitiveWrapper<ChunkedMac, ChunkedMac> {

  private static final ChunkedMacWrapper WRAPPER = new ChunkedMacWrapper();

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof MacKey) {
      return ((MacKey) key).getOutputPrefix();
    }
    if (key instanceof LegacyProtoKey) {
      return ((LegacyProtoKey) key).getOutputPrefix();
    }
    throw new GeneralSecurityException(
        "Cannot get output prefix for key of class "
            + key.getClass().getName()
            + " with parameters "
            + key.getParameters());
  }

  private static class WrappedChunkedMacVerification implements ChunkedMacVerification {
    private final List<ChunkedMacVerification> verifications;

    private WrappedChunkedMacVerification(List<ChunkedMacVerification> verificationEntries) {
      this.verifications = verificationEntries;
    }

    @Override
    public void update(ByteBuffer data) throws GeneralSecurityException {
      // We will need to be `reset()`ting this buffer due to potentially multiple reads from the
      // same data span in order to be consistent with the behaviour of ChunkedMacComputation
      // wrapper. That is, after the execution, user's buffer's `mark` is left unchanged, and its
      // `position` is equal to `limit` after we finished reading from the buffer. In order to
      // achieve that we `duplicate()` the given `data` buffer here and set `mark()`s on the cloned
      // buffer (note that the `duplicate()` method does not copy the underlying data).
      ByteBuffer clonedData = data.duplicate();
      clonedData.mark();
      for (ChunkedMacVerification entry : verifications) {
        clonedData.reset();
        entry.update(clonedData);
      }
      data.position(data.limit());
    }

    @Override
    public void verifyMac() throws GeneralSecurityException {
      GeneralSecurityException errorSink =
          new GeneralSecurityException("MAC verification failed for all suitable keys in keyset");
      for (ChunkedMacVerification entry : verifications) {
        try {
          entry.verifyMac();
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored as we want to continue verification with the remaining keys.
          errorSink.addSuppressed(e);
        }
      }
      // nothing works.
      throw errorSink;
    }
  }

  @Immutable
  private static class WrappedChunkedMac implements ChunkedMac {
    private final PrefixMap<ChunkedMac> allChunkedMacs;

    private final ChunkedMac primaryChunkedMac;

    private WrappedChunkedMac(PrefixMap<ChunkedMac> allChunkedMacs, ChunkedMac primaryChunkedMac) {
      this.allChunkedMacs = allChunkedMacs;
      this.primaryChunkedMac = primaryChunkedMac;
    }

    @Override
    public ChunkedMacComputation createComputation() throws GeneralSecurityException {
      return primaryChunkedMac.createComputation();
    }

    @Override
    public ChunkedMacVerification createVerification(final byte[] tag)
        throws GeneralSecurityException {
      List<ChunkedMacVerification> allVerifications = new ArrayList<>();
      for (ChunkedMac mac : allChunkedMacs.getAllWithMatchingPrefix(tag)) {
        allVerifications.add(mac.createVerification(tag));
      }
      return new WrappedChunkedMacVerification(allVerifications);
    }
  }

  private ChunkedMacWrapper() {}

  @Override
  public ChunkedMac wrap(
      final PrimitiveSet<ChunkedMac> primitives, PrimitiveFactory<ChunkedMac> factory)
      throws GeneralSecurityException {
    if (primitives == null) {
      throw new GeneralSecurityException("primitive set must be non-null");
    }
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    KeysetHandleInterface.Entry primaryEntry = keysetHandle.getPrimary();
    if (primaryEntry == null) {
      throw new GeneralSecurityException("no primary in primitive set");
    }
    PrefixMap.Builder<ChunkedMac> allChunkedMacsBuilder = new PrefixMap.Builder<ChunkedMac>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      ChunkedMac chunkedMac = factory.create(entry);
      allChunkedMacsBuilder.put(getOutputPrefix(entry.getKey()), chunkedMac);
    }
    ChunkedMac primaryChunkedMac = factory.create(primaryEntry);

    return new WrappedChunkedMac(allChunkedMacsBuilder.build(), primaryChunkedMac);
  }

  @Override
  public Class<ChunkedMac> getPrimitiveClass() {
    return ChunkedMac.class;
  }

  @Override
  public Class<ChunkedMac> getInputPrimitiveClass() {
    return ChunkedMac.class;
  }

  static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code MacWrapper} to the provided {@code
   * PrimitiveRegistry#Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
