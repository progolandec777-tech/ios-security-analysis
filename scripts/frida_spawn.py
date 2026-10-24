#!/usr/bin/env python3
"""
Frida dynamic analysis via spawn mode.
Bypasses SIP task_for_pid restriction by using device.spawn() instead of attach.
Usage: python3 frida_spawn.py <sim_udid> <reports_dir>
"""
import frida
import sys
import time
import os

sim_udid = sys.argv[1]
reports_dir = sys.argv[2]
os.makedirs(reports_dir, exist_ok=True)

print(f"[+] Connecting to simulator {sim_udid}...", flush=True)
try:
    device = frida.get_device(sim_udid, timeout=15)
    print(f"[+] Device: {device.name} ({device.id})", flush=True)
except Exception as e:
    print(f"[-] Cannot get device: {e}")
    sys.exit(0)

HOOK_JS = r"""
// ===== ObjC CLASS ENUMERATION =====
(function() {
  if (!ObjC.available) { send('[INFO] ObjC not available'); return; }
  try {
    var loaded = ObjC.enumerateLoadedClassesSync();
    var total = 0;
    for (var img in loaded) {
      if (img.indexOf('.app') !== -1) {
        var cls = loaded[img];
        send('[CLASS_IMG] ' + img + ' (' + cls.length + ' classes)');
        cls.forEach(function(c) { send('[CLASS] ' + c); total++; });
      }
    }
    send('[CLASS_TOTAL] App-owned classes: ' + total);
  } catch(e) { send('[CLASS_ERR] ' + e); }
})();

// ===== NETWORK HOOKS =====
(function() {
  if (!ObjC.available) return;
  try {
    var NSURLSession = ObjC.classes.NSURLSession;
    var m = NSURLSession['- dataTaskWithRequest:completionHandler:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function(args) {
          try {
            var req = new ObjC.Object(args[2]);
            send('[NETWORK] ' + req.URL().toString() + ' [' + req.HTTPMethod().toString() + ']');
          } catch(e) {}
        }
      });
    }
    var m2 = NSURLSession['- dataTaskWithURL:completionHandler:'];
    if (m2) {
      Interceptor.attach(m2.implementation, {
        onEnter: function(args) {
          try { send('[NETWORK] URL: ' + new ObjC.Object(args[2]).toString()); } catch(e) {}
        }
      });
    }
    send('[NETWORK_HOOK] NSURLSession hooks installed');
  } catch(e) { send('[NETWORK_ERR] ' + e); }
})();

// ===== KEYCHAIN HOOKS =====
(function() {
  try {
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) { send('[KEYCHAIN] SecItemCopyMatching called'); },
        onLeave: function(ret) { send('[KEYCHAIN] result=' + ret.toInt32()); }
      });
    }
    var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    if (SecItemAdd) {
      Interceptor.attach(SecItemAdd, {
        onEnter: function(args) { send('[KEYCHAIN] SecItemAdd called'); }
      });
    }
    send('[KEYCHAIN_HOOK] Keychain hooks installed');
  } catch(e) { send('[KEYCHAIN_ERR] ' + e); }
})();

// ===== NSUSERDEFAULTS HOOKS =====
(function() {
  if (!ObjC.available) return;
  try {
    var UD = ObjC.classes.NSUserDefaults;
    var setObj = UD['- setObject:forKey:'];
    if (setObj) {
      Interceptor.attach(setObj.implementation, {
        onEnter: function(args) {
          try {
            var key = new ObjC.Object(args[3]).toString();
            var val = new ObjC.Object(args[2]).toString();
            send('[DEFAULTS] SET ' + key + ' = ' + val.substring(0, 100));
          } catch(e) {}
        }
      });
    }
    send('[DEFAULTS_HOOK] NSUserDefaults hooks installed');
  } catch(e) { send('[DEFAULTS_ERR] ' + e); }
})();

// ===== CRYPTO HOOKS =====
(function() {
  try {
    var CCCrypt = Module.findExportByName(null, 'CCCrypt');
    if (CCCrypt) {
      Interceptor.attach(CCCrypt, {
        onEnter: function(args) { send('[CRYPTO] CCCrypt op=' + args[0].toInt32()); }
      });
    }
    send('[CRYPTO_HOOK] CCCrypt=' + (CCCrypt ? 'hooked' : 'not found'));
  } catch(e) { send('[CRYPTO_ERR] ' + e); }
})();

// ===== FILE ACCESS HOOKS =====
(function() {
  if (!ObjC.available) return;
  try {
    var FM = ObjC.classes.NSFileManager;
    var exists = FM['- fileExistsAtPath:'];
    if (exists) {
      Interceptor.attach(exists.implementation, {
        onEnter: function(args) {
          try {
            var p = new ObjC.Object(args[2]).toString();
            if (p && p.indexOf('/System') === -1 && p.indexOf('/usr') === -1) {
              send('[FILE] exists: ' + p);
            }
          } catch(e) {}
        }
      });
    }
    send('[FILE_HOOK] NSFileManager hooks installed');
  } catch(e) { send('[FILE_ERR] ' + e); }
})();

send('[FRIDA_READY] All hooks active, waiting for app activity...');
"""

output = []


def on_msg(m, d):
    if m['type'] == 'send':
        line = str(m['payload'])
        print(line, flush=True)
        output.append(line)
    elif m['type'] == 'error':
        err = m.get('description', str(m))
        print('[JS-ERR] ' + err, flush=True)


def try_spawn(bundle_id, label, collect_secs=30):
    print(f"\n[+] Spawning {label} ({bundle_id})...", flush=True)
    try:
        pid = device.spawn(bundle_id)
        print(f"[+] Spawned PID={pid}", flush=True)
        session = device.attach(pid)
        script = session.create_script(HOOK_JS)
        script.on('message', on_msg)
        script.load()
        device.resume(pid)
        print(f"[+] App running, collecting for {collect_secs}s...", flush=True)
        time.sleep(collect_secs)
        try:
            session.detach()
        except Exception:
            pass
        return True
    except Exception as e:
        print(f"[-] Spawn/attach failed for {label}: {e}")
        return False


# Attempt 1: DVIA-v2 (target app for security analysis)
ok = try_spawn("com.highaltitudehacks.DVIAswiftv2", "DVIA-v2", 30)

# Attempt 2: MobileSafari (always available on simulator)
if not ok:
    output.append("[INFO] DVIA-v2 failed, trying MobileSafari")
    ok = try_spawn("com.apple.mobilesafari", "MobileSafari", 20)

# Attempt 3: SpringBoard (always running system process)
if not ok:
    output.append("[INFO] MobileSafari failed, trying SpringBoard attach")
    try:
        procs = device.enumerate_processes()
        spring = next((p for p in procs if p.name == 'SpringBoard'), None)
        if spring:
            print(f"[+] Attaching to SpringBoard PID={spring.pid}...", flush=True)
            session = device.attach(spring.pid)
            script = session.create_script(HOOK_JS)
            script.on('message', on_msg)
            script.load()
            time.sleep(15)
            session.detach()
            ok = True
    except Exception as e:
        print(f"[-] SpringBoard attach: {e}")

# Always list running processes
try:
    procs = device.enumerate_processes()
    output.append("[PROCESSES] Running on simulator:")
    for p in procs:
        line = f"[PROCESS] PID={p.pid:6d}  {p.name}"
        print(line, flush=True)
        output.append(line)
except Exception as e:
    print(f"[-] enumerate_processes: {e}")

# Write reports
with open(f"{reports_dir}/frida-full.txt", "w") as f:
    f.write("\n".join(output))
with open(f"{reports_dir}/frida-classes.txt", "w") as f:
    f.write("\n".join(l for l in output if '[CLASS' in l))
with open(f"{reports_dir}/frida-network.txt", "w") as f:
    f.write("\n".join(l for l in output if '[NETWORK]' in l))
with open(f"{reports_dir}/frida-keychain.txt", "w") as f:
    f.write("\n".join(l for l in output if '[KEYCHAIN]' in l))
with open(f"{reports_dir}/frida-defaults.txt", "w") as f:
    f.write("\n".join(l for l in output if '[DEFAULTS]' in l))
with open(f"{reports_dir}/frida-crypto.txt", "w") as f:
    f.write("\n".join(l for l in output if '[CRYPTO]' in l))

classes_count = sum(1 for l in output if l.startswith('[CLASS]'))
network_count = sum(1 for l in output if l.startswith('[NETWORK]'))
keychain_count = sum(1 for l in output if l.startswith('[KEYCHAIN]'))

print(f"\n[+] Total events: {len(output)}")
print(f"[+] Classes: {classes_count}")
print(f"[+] Network: {network_count}")
print(f"[+] Keychain: {keychain_count}")
print(f"[+] Reports saved to {reports_dir}/")
