rule Win_Trojan_Bwg_2
{
strings:
	$a0 = { 636f707920633a5c }
	$a1 = { 2e626174202577696e646972255c73746172746d7e315c70726f6772616d735c737461727475705c }
	$a2 = { 2e626174 }

condition:
	$a0 and $a1 and $a2
}

        
