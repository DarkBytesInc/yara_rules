rule Xls_Trojan_Soldier_8
{
strings:
	$a0 = { 576f726b626f6f6b7328666e24292e4d6f64756c65732831292e496e7365727446696c652066696c654e616d653a3d22633a5c736f6c646965722e5f5f5f222c204d657267653a3d54727565 }

condition:
	$a0
}

        