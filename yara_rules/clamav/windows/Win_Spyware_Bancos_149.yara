rule Win_Spyware_Bancos_149
{
strings:
	$a0 = { 240070662078797a7a79206d6173746572207075706574732072657475726e2074726f6a616e0003004000000480ff800019010042002203233e0400006c740000360400000000010002002020100000000000e8020000260000001010100000000000280100000e03 }

condition:
	$a0
}

        