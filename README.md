# Post-Quantum K-9 Mail 
The open-source email client K-9 Mail, with integrated signing with post-quantum cryptography signature schemes as part of my bachelor thesis, found [here](TODO).

## Supported algorithms
All finalists from [NIST's round 4](TODO) are included in this implementation with their highest security level:
- Dilithium5
- Dilithium5-AES
- Falcon-1024
- Sphincs+-Haraka-256f-simple
- Sphincs+-SHA256-256f-simple
- Sphincs+-SHAKE256-256f-simple

For implementing the algorithms the library [**liboqs**](TODO) from the [Open Quantum Project](TODO) is used. 

## Changes to K-9 

In the settings preferences there is an additional menu about Post-Quantum signature. Inside the user can choose an algorithm used for signing Emails, generate, verify, view, export and import his keys. One set of keys is assumed for every profile added to the application.

[TODO screenshots]

When sending an email a new option for Post-Quantum signing is added when a recipient is entered. The first two times when selecting this option more information about the procedure is given. The sent email contains two files "signature.asc" and "public_key.asc" in plain text, which contain the name of the aglorithm used and the signature and public key respectively.

[TODO screenshots]

The final addition to the UI is when opening a Post-Quantum signed Email. The user does not see the attachments and the check mark in the upper right states PQS if the Email has been signed and not modified. More information about the algorithm used is represented when clicking on the check mark. If the signature or public key do not match the used algorithm and message a red lock is given and more information is shown.

[TODO screenshots]

Other major changes, besides the addition of multiple new classes and activities, include change of the size for the automatic attachment loading, because of the huge signature sizes of Sphincs+ and the minimum supported SDK (only for the PQS), because of encoding issues with older Android versions.

## Liboqs 

#### Changes

The current version of implementing the **liboqs** library is by frequent compilation for Android and implementation as a plugin with the included [wrapper](TODO). This is inefficient, until a standard from NIST is given, but the other option OpenSSL needs root to run sistem wide. 

#### Compilation

First step is building **liboqs** in Linux as stated in [the repository](TODO). 
Afterwards, the script [*build-android.sh*](https://github.com/open-quantum-safe/liboqs/blob/main/scripts/build-android.sh) inside the repository can be executed to build the *.so* file for the needed Android ABI. Also the NDK and minimum SDK must be known/present. Here used are *armeabi-v7a* ABI and 21 as the version of the SDK. 
The next step is compiling [the Java wrapper](TODO) per the instructions included. Needed is a slight modification of the method of loading the *.so* file, seen [here](TODO) and unifing the package names and imports to match the previously compiled ones. 
Last addition needed is an *Android.mk* file, containing for creating the JNI wrapper. 
All of them need to be combined: from the first step the *.h*, *.c* files; from the second the *.so*; from the third the *.java* files and the *.mk* from the last step. Everything is inside the **liboqs-android** package.


For the compilation of the whole project gradle and Android studio take care of everything.

## License

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
