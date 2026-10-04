#!/usr/bin/env python3
"""Re-sign an unsigned WebDriverAgentRunner-Runner.app with the development
certificate + provisioning profile that Codemagic's ios_signing installed,
then zip it into an IPA. Fails loudly on any mismatch."""
import argparse, glob, hashlib, os, plistlib, shutil, subprocess, sys, tempfile

ap = argparse.ArgumentParser()
ap.add_argument("--app", required=True)
ap.add_argument("--bundle-id", required=True)
ap.add_argument("--udid", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()

def run(cmd, **kw):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)

# 1. Sanity: the app must carry the bundle id we registered.
info = plistlib.load(open(os.path.join(a.app, "Info.plist"), "rb"))
print("App CFBundleIdentifier:", info["CFBundleIdentifier"])
if info["CFBundleIdentifier"] != a.bundle_id:
    sys.exit(f"ERROR: app bundle id {info['CFBundleIdentifier']} != expected {a.bundle_id}")

# 2. Find a profile for this bundle id that includes the device.
pdirs = [os.path.expanduser("~/Library/MobileDevice/Provisioning Profiles"),
         os.path.expanduser("~/Library/Developer/Xcode/UserData/Provisioning Profiles")]
chosen = None
profiles = sorted(p for d in pdirs for p in glob.glob(os.path.join(d, "*.mobileprovision")))
print("profiles found:", profiles)
for p in profiles:
    prof = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", p]))
    appid = prof["Entitlements"]["application-identifier"].split(".", 1)[1]
    devices = prof.get("ProvisionedDevices", [])
    print(f"profile {os.path.basename(p)}: name={prof['Name']!r} appid={appid} "
          f"devices={len(devices)} has_udid={a.udid in devices}")
    if appid in (a.bundle_id, "*") and a.udid in devices:
        chosen = (p, prof)
        break
if not chosen:
    sys.exit("ERROR: no development profile matches the bundle id AND contains the device UDID")
ppath, prof = chosen

# 3. Pick the signing identity whose cert is inside the profile.
want = {hashlib.sha1(c).hexdigest().upper() for c in prof["DeveloperCertificates"]}
ids = subprocess.check_output(["security", "find-identity", "-v", "-p", "codesigning"]).decode()
identity = None
for line in ids.splitlines():
    parts = line.split()
    if len(parts) > 1 and parts[1].upper() in want:
        identity = parts[1]
        print("Using identity:", line.strip())
        break
if not identity:
    sys.exit("ERROR: no keychain identity matches a certificate in the profile\n" + ids)

# 4. Entitlements from the profile.
work = tempfile.mkdtemp()
ent = os.path.join(work, "ent.plist")
with open(ent, "wb") as f:
    plistlib.dump(prof["Entitlements"], f)

# 5. Embed profile, sign inside-out, then the app.
shutil.copy(ppath, os.path.join(a.app, "embedded.mobileprovision"))
nested = []
for root, dirs, files in os.walk(a.app, topdown=False):
    for n in dirs + files:
        if n.endswith((".framework", ".xctest", ".appex", ".dylib")):
            nested.append(os.path.join(root, n))
for n in nested:
    run(["codesign", "--force", "--sign", identity, "--timestamp=none", n])
run(["codesign", "--force", "--sign", identity, "--entitlements", ent, "--timestamp=none", a.app])
run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", a.app])

# 6. Package.
payload = os.path.join(work, "Payload")
os.makedirs(payload)
shutil.copytree(a.app, os.path.join(payload, os.path.basename(a.app)), symlinks=True)
out = os.path.abspath(a.out)
if os.path.exists(out):
    os.remove(out)
run(["zip", "-qry", out, "Payload"], cwd=work)
print("IPA:", out, os.path.getsize(out), "bytes")
