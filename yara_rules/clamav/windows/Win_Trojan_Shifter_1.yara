rule Win_Trojan_Shifter_1
{
strings:
	$a0 = { fecd213d0dd07503eb54908cd8488ed8812e03008000812e1200800033c08ed8832e130402a11304b106d3e00e1f2d10008ec0bf0001be0001b9d703f2a4 }

condition:
	$a0
}

        
