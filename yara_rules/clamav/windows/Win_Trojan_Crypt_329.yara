rule Win_Trojan_Crypt_329
{
strings:
	$a0 = { eb425d8d7d0c8b6d008b77f88b5ffc31c98d46010fb6f00fb614378d041a0fb6d80fb6041f88043788141f01d00fb6c00fb60407308100c047004139cd7fd2e911010000e8b9ffffff }

condition:
	$a0
}

        
