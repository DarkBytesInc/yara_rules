rule Win_Dropper_Agent_33436
{
strings:
	$a0 = { 5ae0d06b560f9ee8d243a90ca2f69ed02cbafdbc9ad9b4063e397bc7015971d819b0980692aaf1f199b1cf7f4ae8e38a94dafdd5285c52f78f1afcac9f2a7917320d6eac3461099bd99df06d746bd86a724c44c62c4d9860aedb9af99a84275eb72ec7ffff79 }

condition:
	$a0
}

        
