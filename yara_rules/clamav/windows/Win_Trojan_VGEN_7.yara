rule Win_Trojan_VGEN_7
{
strings:
	$a0 = { 01501e06ba44008ec226a100013b0600017421be000189f7b9e001f3a4061fb82135cd21891ec1018c06c301b821 }

condition:
	$a0
}

        
