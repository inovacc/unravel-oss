/*
Copyright (c) 2026 Security Research
*/
package native

// patternDef defines a string pattern to search for in .rodata sections.
type patternDef struct {
	pattern     string
	severity    string
	description string
}

// packerDef defines a packer/protector signature.
type packerDef struct {
	signature   string
	name        string
	severity    string
	description string
}

// antiDebugPatterns contains strings found in .rodata indicating anti-debug techniques.
var antiDebugPatterns = []patternDef{
	{"ptrace", "high", "ptrace anti-debug call"},
	{"TracerPid", "high", "Checks /proc/self/status for debugger"},
	{"android_dlopen_ext", "medium", "Dynamic library loading"},
}

// rootDetectionPatterns contains strings indicating root/jailbreak detection.
var rootDetectionPatterns = []patternDef{
	{"/system/xbin/su", "medium", "Checks for su binary"},
	{"/system/app/Superuser.apk", "medium", "Checks for Superuser app"},
	{"com.noshufou.android.su", "medium", "Checks for SuperSU package"},
	{"com.topjohnwu.magisk", "medium", "Checks for Magisk"},
	{"/sbin/su", "medium", "Checks for su in sbin"},
	{"test-keys", "low", "Checks build tags for test-keys"},
}

// emulatorDetectionPatterns contains strings indicating emulator detection.
var emulatorDetectionPatterns = []patternDef{
	{"goldfish", "medium", "Emulator hardware detection"},
	{"ranchu", "medium", "Emulator hardware detection"},
	{"generic_x86", "low", "Generic x86 device detection"},
	{"google_sdk", "low", "SDK emulator detection"},
	{"sdk_gphone", "low", "SDK phone emulator detection"},
}

// packerSignatures contains byte/string signatures of known packers and protectors.
var packerSignatures = []packerDef{
	{"UPX!", "UPX", "high", "UPX packer detected"},
	{"libsecexe.so", "Bangcle", "high", "Bangcle packer"},
	{"libDexHelper.so", "DEXProtector", "high", "DEXProtector"},
	{"libjiagu.so", "360 Jiagu", "high", "360 packer"},
	{"libshella", "Tencent Legu", "high", "Tencent Legu packer"},
	{"libtosprotection", "Tencent", "high", "Tencent protection"},
	{"ijiami", "Ijiami", "high", "Ijiami packer"},
}
