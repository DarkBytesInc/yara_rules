rule Win_Trojan_4224_1
{
strings:
	$a0 = { 909000000000cd2190e95ffb3c7090e9d6f9cd2190c379b69090000000008ae090c3b8c390900000 }

condition:
	$a0
}

        
