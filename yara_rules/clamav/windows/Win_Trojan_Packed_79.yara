rule Win_Trojan_Packed_79
{
strings:
	$a0 = { 8d475039c50f87??01000089e28d4f4029d18d458029c889c49c5689d68d7c08c05789c7fcf3a45f5e9d }
	$a1 = { 68000000008b74242c89e581ecc000000089e7037500 }

condition:
	$a0 and $a1
}

        
