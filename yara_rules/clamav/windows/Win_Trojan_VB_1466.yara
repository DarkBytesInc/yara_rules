rule Win_Trojan_VB_1466
{
strings:
	$a0 = { 0e44d3a83cc2083883a1efe2bfd16c9f019a247cfefc4d320f0bd74a1816375b8fa5b4c5401007e99bf23c3161883f4cf40225f9799cb6f5fe7d4462fe4f474235a78a272f1d5feacd7675966b8cecef91ff491ee3893850d1af24074b6984f7adfd21970979e2642eb3f593fd033a8664849c3b47a9489422dca13cd18f23500e9b412c1b9d536ce0fc0282 }

condition:
	$a0
}

        