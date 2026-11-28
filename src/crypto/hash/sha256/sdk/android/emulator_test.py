"""Install the clean consumer APK in a fresh x86_64 Android emulator."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from package import ROOT, default_sdk, required_file


AVD = "ABC_API36_Consumer"
IMAGE = "system-images/android-36/google_apis_playstore/x86_64"
APP = "org.allbasket.abc.android.consumer/.ProbeActivity"
PASS = "SHA-256 AAR consumer passed"


def prepare_avd(directory, sdk):
    required_file(sdk / IMAGE / "package.xml")
    home = directory / "avd"
    device = home / f"{AVD}.avd"
    device.mkdir(parents=True)
    (home / f"{AVD}.ini").write_text(f"avd.ini.encoding=UTF-8\npath={device.as_posix()}\ntarget=android-36\n",
                                      encoding="utf-8", newline="\n")
    (device / "config.ini").write_text(f'''AvdId={AVD}
avd.ini.displayname=ABC Android SDK Consumer
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=2
hw.ramSize=2048
hw.lcd.width=1080
hw.lcd.height=1920
hw.lcd.density=320
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
disk.dataPartition.size=2G
PlayStore.enabled=true
tag.id=google_apis_playstore
tag.display=Google Play
image.sysdir.1={IMAGE}/
''', encoding="utf-8", newline="\n")
    return home


def available_ports(ports):
    for port in ports:
        with socket.socket() as local:
            local.bind(("127.0.0.1", port))


def verify(sdk, apk, port, adb_port):
    suffix = ".exe" if os.name == "nt" else ""
    emulator = required_file(sdk / "emulator" / f"emulator{suffix}")
    adb = required_file(sdk / "platform-tools" / f"adb{suffix}")
    available_ports((port, port + 1, adb_port))
    cache = ROOT / ".abc/android"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="emulator-", dir=cache, ignore_cleanup_errors=os.name == "nt") as temporary:
        directory = Path(temporary)
        user = directory / "user"
        user.mkdir()
        environment = {**os.environ, "ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": str(sdk),
                       "ANDROID_AVD_HOME": str(prepare_avd(directory, sdk)), "ANDROID_USER_HOME": str(user),
                       "ANDROID_ADB_SERVER_PORT": str(adb_port), "ADB_SERVER_SOCKET": f"tcp:localhost:{adb_port}"}
        serial = f"127.0.0.1:{port + 1}"

        def control(*args, check=True):
            return subprocess.run([adb, "-P", str(adb_port), *args], env=environment, capture_output=True,
                                  encoding="utf-8", errors="replace", timeout=60, check=check)

        logfile = directory / "emulator.log"
        control("start-server")
        with logfile.open("wb") as log:
            process = subprocess.Popen(
                [emulator, "-avd", AVD, "-no-window", "-no-audio", "-no-snapshot", "-no-boot-anim",
                 "-gpu", "swiftshader_indirect", "-port", str(port)], env=environment, stdout=log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                deadline = time.monotonic() + 210
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"emulator exited with code {process.returncode}")
                    control("connect", serial, check=False)
                    if control("-s", serial, "shell", "getprop", "sys.boot_completed", check=False).stdout.strip() == "1":
                        break
                    time.sleep(3)
                else:
                    raise RuntimeError("isolated Android emulator did not boot within 210 seconds")
                status = control("-s", serial, "install", str(apk)).stdout.strip()
                if status.splitlines()[-1] != "Success":
                    raise RuntimeError(f"APK installation did not succeed: {status}")
                control("-s", serial, "shell", "am", "start", "-W", "-n", APP)
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    reported = control("-s", serial, "logcat", "-d", "-s", "ABC-SDK:I", "AndroidRuntime:E", "*:S").stdout
                    if PASS in reported:
                        abi = control("-s", serial, "shell", "getprop", "ro.product.cpu.abi").stdout.strip()
                        api = control("-s", serial, "shell", "getprop", "ro.build.version.sdk").stdout.strip()
                        if abi != "x86_64" or api != "36":
                            raise RuntimeError(f"unexpected Android consumer target: {abi} API {api}")
                        return {"source": "emulator", "abi": abi, "api": int(api), "result": PASS}
                    if "FATAL EXCEPTION" in reported:
                        raise RuntimeError(reported)
                    time.sleep(2)
                raise RuntimeError("consumer did not produce its success marker")
            except (OSError, RuntimeError, subprocess.SubprocessError):
                print(logfile.read_text(encoding="utf-8", errors="replace")[-8000:], flush=True)
                raise
            finally:
                control("-s", serial, "emu", "kill", check=False)
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=30)
                control("kill-server", check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=default_sdk())
    parser.add_argument("--apk", type=Path, default=ROOT / "dist/android/abc-android-consumer-debug.apk")
    parser.add_argument("--port", type=int, default=5584)
    parser.add_argument("--adb-port", type=int, default=5039)
    args = parser.parse_args()
    if not args.sdk or not (5554 <= args.port <= 5682 and args.port % 2 == 0 and 1 <= args.adb_port <= 65535):
        parser.error("provide the Android SDK and non-conflicting emulator/ADB ports")
    try:
        print(json.dumps(verify(args.sdk.resolve(), required_file(args.apk.resolve()), args.port, args.adb_port)))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Android emulator check failed: {error}\n")


if __name__ == "__main__":
    main()
