rule Win_Trojan_Delf_1042
{
strings:
	$a0 = { 5545c42374534b6739665709f4f913ed65640fbd9f2c6100367035dd44cb0e6ae0349d1d0bedf927796224ceaab5823477df1d1f1cbbcb1fb5d4a3a7ebe36e4ce8d313dfb0fb5e9e9f1a3d7dc6c0028b81cb2adf7c369c50e9 }

condition:
	$a0
}

        
