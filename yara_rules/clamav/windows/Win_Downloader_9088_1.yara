rule Win_Downloader_9088_1
{
strings:
	$a0 = { 558bec83c4f0b830994000e89cb2ffffb8109a4000e88ac3ffffb82c9a4000e880c3ffffb8489a4000e876c3ffffb8649a4000e86cc3ffffb8809a4000e862c3ffffb89c9a4000e858c3ffffb8b89a4000e84ec3ffffb8d49a4000e844c3ffffb8f09a4000e83ac3ffffb80c9b4000e830c3ffffe8a3f6ffff }

condition:
	$a0
}

        
