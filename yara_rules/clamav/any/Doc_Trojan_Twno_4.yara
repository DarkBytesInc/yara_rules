rule Doc_Trojan_Twno_4
{
strings:
	$a0 = { 746f6724202b202220b36fb458add3bcc6a672c5fda741c170b751a8ecadfea8e2a6ecbcc6a94f3fb5aaaed7a94da4e9b4c1a6b3c3f621a55bb4eeadbcb0a3c048ab4ba74121222c2022a3ab202020aba22021a741aabab4bcb0d3b657b94c313830b6dc3f202229 }

condition:
	$a0
}

        
