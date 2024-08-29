// Copyright 2024 Google LLC
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

package com.google.crypto.tink.aead;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;

/** Describes the parameters of an {@link XAesGcmKey} */
public final class XAesGcmParameters extends AeadParameters {
  /**
   * Describes how the prefix is computed. For AEAD, there are two possibilities: either NO_PREFIX
   * (empty prefix) or TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big
   * endian format).
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant NO_PREFIX = new Variant("NO_PREFIX");

    private final String name;

    private Variant(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  public static XAesGcmParameters create(Variant variant, int saltSizeBytes)
      throws GeneralSecurityException {
    if (saltSizeBytes < 8 || saltSizeBytes > 12) {
      throw new GeneralSecurityException("Salt size must be between 8 and 12 bytes");
    }
    return new XAesGcmParameters(variant, saltSizeBytes);
  }

  private final Variant variant;
  private final int saltSizeBytes;

  private XAesGcmParameters(Variant variant, int saltSizeBytes) {
    this.variant = variant;
    this.saltSizeBytes = saltSizeBytes;
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  public int getSaltSizeBytes() {
    return saltSizeBytes;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof XAesGcmParameters)) {
      return false;
    }
    XAesGcmParameters that = (XAesGcmParameters) o;
    return that.getVariant() == getVariant() && that.getSaltSizeBytes() == getSaltSizeBytes();
  }

  @Override
  public int hashCode() {
    return Objects.hash(XAesGcmParameters.class, variant, saltSizeBytes);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "X-AES-GCM Parameters (variant: " + variant + "salt_size_bytes: " + saltSizeBytes + ")";
  }
}
