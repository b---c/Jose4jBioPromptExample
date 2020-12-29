# jose4j BiometricPrompt AndroidKeyStore Example App

A very simple Android project that shows how to use jose4j with Android keystore system
keys that require user biometric authentication for use. This could be used, for example,
to require that the user present a biometric each time a particular key is used to sign a JWT.

`MainActivity` is where the magic happens, so look there to see the actual workings. But basically, after setting the private key on the JWS or JWE object,
calling the [prepareSigningPrimitive](https://www.javadoc.io/static/org.bitbucket.b_c/jose4j/0.7.3/org/jose4j/jws/JsonWebSignature.html#prepareSigningPrimitive())
or [prepareDecryptingPrimitive()](https://www.javadoc.io/static/org.bitbucket.b_c/jose4j/0.7.3/org/jose4j/jwe/JsonWebEncryption.html#prepareDecryptingPrimitive())
method respectively will allow access to the underlying `Signature` or `Cipher`, which can be used to set up a `BiometricPrompt.CryptoObject`
that can authorize use of the crypto object by showing a biometric authentication dialog to the user.

To run it:

1. Open project in android studio
1. Create/pick a destination to run on - emulator or device
1. Ensure your chosen device has finger print and a lock pattern or
pin enabled using the 'Security' section of the on-device settings app
1. Run the project (on a device or an emulator)
1. Enter some text and tap the button to "Sign & Verify" or "Encrypt & Decrypt"
1. Present fingerprint when prompted (on the emulator, hit the '...'
on the toolbar on the right hand side to open 'Extended Controls' then
select 'Fingerprint' and 'touch the sensor')
1. The text as well as the actual JWS or JWE will be shown
1. Profit?
