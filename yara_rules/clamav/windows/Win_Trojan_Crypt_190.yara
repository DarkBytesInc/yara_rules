rule Win_Trojan_Crypt_190
{
strings:
	$a0 = { 780550c0c32858f851770681ed000000005956526ab583c4045a5e507b037501f858f5606683f1 }

condition:
	$a0
}

        
