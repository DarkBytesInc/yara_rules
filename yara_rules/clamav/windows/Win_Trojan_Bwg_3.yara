rule Win_Trojan_Bwg_3
{
strings:
	$a0 = { 25257620696e20282a2e626174202e2e5c2a2e626174205c2a2e626174202570617468255c2a2e6261742920646f20636f707920633a5c }
	$a1 = { 2e626174202525762064656c }

condition:
	$a0 and $a1
}

        