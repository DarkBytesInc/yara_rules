rule Doc_Trojan_CMK_1
{
strings:
	$a0 = { 4465636973696f6e203d204d7367426f78282257616e6e61206578697420434d4b3f222c2033362c2022434d4b2076312e302229 }

condition:
	$a0
}

        