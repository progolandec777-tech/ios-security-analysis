// Frida hook script for DVIA-v2 (iOS Simulator)
// Usage (macOS): frida -D <UDID> -n DVIA-v2 -l frida_hook_dvia.js
// Requirement: frida >= 17.4, iOS Simulator booted, DVIA-v2 running

'use strict';

console.log("[*] DVIA-v2 Frida hook loaded");

// Hook 1: Log all Objective-C class loads (noisy, good for enumeration)
// Interceptor.attach(ObjC.classes.NSObject['+ load'].implementation, {
//     onEnter: function(args) { console.log('load:', ObjC.Object(args[0])); }
// });

// Hook 2: Intercept NSUserDefaults setObject:forKey: (credentials check)
if (ObjC.available) {
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    if (NSUserDefaults) {
        Interceptor.attach(
            NSUserDefaults['- setObject:forKey:'].implementation,
            {
                onEnter: function(args) {
                    var key = ObjC.Object(args[3]).toString();
                    var value = ObjC.Object(args[2]).toString();
                    console.log('[NSUserDefaults] setObject:' + value + ' forKey:' + key);
                }
            }
        );
        console.log("[*] NSUserDefaults hook installed");
    }

    // Hook 3: Intercept CommonCrypto CCCrypt (detect crypto usage)
    var ccCrypt = Module.findExportByName("libSystem.B.dylib", "CCCrypt");
    if (ccCrypt) {
        Interceptor.attach(ccCrypt, {
            onEnter: function(args) {
                var op = args[0].toInt32(); // 0=encrypt, 1=decrypt
                console.log('[CCCrypt] op=' + (op === 0 ? 'encrypt' : 'decrypt'));
            }
        });
        console.log("[*] CCCrypt hook installed");
    }
} else {
    console.log("[!] ObjC runtime not available");
}

console.log("[*] All hooks installed. Interact with the app to see output.");
