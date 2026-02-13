// Copyright 2026 Google LLC
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

/**
 * Represents annotations which can be attached to a {@link KeysetHandle} and later retrieved.
 *
 * <p>Annotations can be set in a {@link KeysetHandle} at the time of creation, and can later be
 * obtained with {@link KeysetHandle#getAnnotationsOrNull}. This is useful when one wants to add
 * external information to the keyset handle (e.g. for monitoring) without changing the whole call
 * stack.
 *
 * <p>We note that annotations are not copied when a keyset is copied (e.g., by creating a {@link
 * KeysetHandle.Builder}).
 */
public interface Annotations {}
