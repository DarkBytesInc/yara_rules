rule Win_Trojan_Ada_2
{
strings:
	$a0 = { 1372189cbf00012e8b36620303f7b9280a90d1e9fcfa0e57f3a5cf8cc88ed8c606450200c60648020133c08ec026c50684002ea33d022e8c1e3f0226c5 }

condition:
	$a0
}

        
