rule Win_Spyware_573_2
{
strings:
	$a0 = { 1a68a1602753a0c335c9958d06c7e68de63b653a8ad62a5dbe37b364a09f0cb6f2381f60038fb216f9faabe8ce2e0f6daab7ae6eee243a72fb183ea674c17df0c966c457e7ebaee896ffc843d83d9a4d3de29904404dcd31227ffcb944e3ecfcdfa9c28c7cabfeef83e4dc27ff4969ee8bc0a6476bd1 }

condition:
	$a0
}

        
