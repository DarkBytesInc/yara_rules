rule Win_Trojan_CVE_2011_3411_1
{
strings:
	$a0 = { 000b000b00000000000000aa00000003a0414141ff }

condition:
	$a0
}

        
