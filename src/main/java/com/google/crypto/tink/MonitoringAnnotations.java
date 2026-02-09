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
 * Represents annotations which can be used for monitoring.
 *
 * <p>MonitoringAnnotations can be set in a {@link KeysetHandle} at the time of creation. They can
 * then obtained when creating the primitive in the {@link Configuration}. This allows to pass
 * through arbitrary data to the configuration, which is used for monitoring within Google.
 */
public interface MonitoringAnnotations {}
