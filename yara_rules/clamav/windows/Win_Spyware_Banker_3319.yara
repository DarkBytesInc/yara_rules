rule Win_Spyware_Banker_3319
{
strings:
	$a0 = { 231493a451cd23728fcb73e9a185274df8f34a24a624974b365be4a33b284eccb313346b05e8375a5638f4c0660777a6a7adc5d1bec006b5662fbff30d38dada3b6dcf589725 }

condition:
	$a0
}

        
