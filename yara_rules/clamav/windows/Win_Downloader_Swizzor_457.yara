rule Win_Downloader_Swizzor_457
{
strings:
	$a0 = { 6d98edaf6adb7697ed16cff00932bc44b8cb933b0be8dc52ea375e4bfdba0841114e2f241416359b49076fb6b2eb36bb8b5cf6f4d759dbfb62354744cfd662082494d39948209a0889dec7c1f51bac9bf5a54bf29461d4b30a88 }

condition:
	$a0
}

        
