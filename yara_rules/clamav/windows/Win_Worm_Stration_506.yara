rule Win_Worm_Stration_506
{
strings:
	$a0 = { 5c0000002e657865000000 }
	$a1 = { c23144240c8b04248b4c2404c1e00833c18b4c2408c1e00833c18b4c240cc1e00833c183c410c3cccccccccccccccccc81ec }

condition:
	$a0 and $a1
}

        
