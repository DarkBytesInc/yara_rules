rule Win_Trojan_VBS_214
{
strings:
	$a0 = { 653d652663687228617363286d6964282226636872283334292622d5f4a6cbf8f8f5f8a6 }

condition:
	$a0
}

        
