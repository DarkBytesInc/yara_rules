rule Win_Trojan_SdBot_2325
{
strings:
	$a0 = { 9bde31bdd0b5f75ca2d5dbe144194a704521b51e79aa6c866ab1afbafdb1f8d40799ee588d1ce4dcfa5f0a516343725db710ce6394cdc84d82c8d91d68d4e543b1929ee98be58f822de9a4e6da70cd84dccceed775 }

condition:
	$a0
}

        
