rule Win_Trojan_Agent_34905
{
strings:
	$a0 = { 27f6181608c21f0b0ee50b156b86422b57e543594fc306afbe08df092e855d0e4190095882db718f6ed2134621e8392a2eb95118dcc935265885351660cfe5cf6467307615d1190a10cdb1d67a7d65176995585763d84d5928b2 }

condition:
	$a0
}

        