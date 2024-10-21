# Android Hello World

This is a simple app that allows encrypting and decrypting strings
with keys stored in private shared preferences. On Android M or newer
the keys are further encrypted with a master key stored in Android
Keystore.

It demonstrates the basic steps of using Tink, namely generating or
loading key material, obtaining a primitive, and using the primitive
to do crypto. It also shows how one can add a dependency on Tink
using Gradle.

You can download tink-java source with:

```shell
git clone https://github.com/tink-crypto/tink-java
```

The easiest way to build this app is to import it to [Android Studio](https://developer.android.com/studio/). You can
also
[build it from the command line](https://developer.android.com/studio/build/building-cmdline).
