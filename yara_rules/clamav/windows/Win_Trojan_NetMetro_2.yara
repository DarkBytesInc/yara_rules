rule Win_Trojan_NetMetro_2
{
strings:
	$a0 = { e8de0000c7120000000500466f726d31000d0117004e6574204d6574726f706f6c6974616e20636c69656e }

condition:
	$a0
}

        
