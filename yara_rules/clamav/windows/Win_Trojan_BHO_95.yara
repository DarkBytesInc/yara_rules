rule Win_Trojan_BHO_95
{
strings:
	$a0 = { c3e27038401256126a128402ee799e96a8b400007e2cd41b00436c6f736548616e646c6500df0200c0650157726974654669950253697a656f665265736f75c1ba002d72630034726561ba05606f4100d5014c6f636be18ecfe2c76164a3006f3d8b736e82639b78ce61466f7200c0046b6e674f626a65637430139f260044507201980bf573009e02546572 }

condition:
	$a0
}

        