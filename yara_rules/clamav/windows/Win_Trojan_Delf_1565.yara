rule Win_Trojan_Delf_1565
{
strings:
	$a0 = { b101ba506c45008bc3e810d6ffff8d4df8ba886c45008bc3e8e9d7ffffff75ec68fc6b45008d95ccfeffff8b86f8020000e8f4c7fdffffb5ccfeffff68086c45008d45f4ba04000000e868dffaffba886c45008bc3e800d9ffff84c0740d8b45f88b55f4e8d1dffaff740f }

condition:
	$a0
}

        
