rule Win_Trojan_Speery_2
{
strings:
	$a0 = { 6c6174696661683d7265706c61636528737563692c636872283831292c636872283133292b6368722831302929 }
	$a1 = { 7261736d616c69616e3d7265706c616365286c6174696661682c63687228313236292c22202229 }
	$a2 = { 76697265733d7265706c616365287261736d616c69616e2c636872283838292c222229 }
	$a3 = { 766972653d7265706c6163652876697265732c636872 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        