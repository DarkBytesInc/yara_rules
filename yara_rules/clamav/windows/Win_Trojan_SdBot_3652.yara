rule Win_Trojan_SdBot_3652
{
strings:
	$a0 = { ad4a3b44ec9eb9dfc72657091102c329d4823f11e32e8834d5086a962db15c95d24fa7fc8fe3ac00624bcd06d1ed47ca23e24fcfc8b8ad2c950bc304e18d27c05e11252422367bb4da627b4ef530 }

condition:
	$a0
}

        
