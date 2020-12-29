# jose4j BiometricPrompt AndroidKeyStore Example App

A very simple Andorid project that shows how to use jose4j with Android keystore system
keys that require user biometric authentication for use.

To run it:

1. Open project in android studio
1. Create/pick a destination to run on - emulator or device
1. Ensure your chosen device has finger print and a lock pattern or
pin enabled using the 'Security' section of the on-device settings app
1. Run the project (on a device or an emulator)
1. Enter some text and tap the button to "Sign & Verify" or "Encrypt & Decrypt"
1. Present fingerprint when prompted (on the emulator, hit the '...'
on the toolbar on the right hand side to open 'Extended Controls' then
select 'Fingerprint' and 'touch the sensor'.
1. The text and the the JWS or JWE will be shown
1. Profit

