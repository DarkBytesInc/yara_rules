rule Win_Downloader_Banload_97
{
strings:
	$a0 = { b8cca84000e8fda3ffffe8989fffff84c00f8475ffffffa19caa40000305a0aa4000b8cca84000e883a3ffffe8769fffff8d45dcb93c8840008b15aca84000e883b7ffff8b45dce843d4ffff84c00f85d6000000b8a4aa40008b0dacaa40008b15a8aa4000e85db7ffff }

condition:
	$a0
}

        
