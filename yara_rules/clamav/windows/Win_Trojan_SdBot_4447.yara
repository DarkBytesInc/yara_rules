rule Win_Trojan_SdBot_4447
{
strings:
	$a0 = { bddaa326b36b7a753e1bcf1b6addc67df8ec5d575661860e8ef47093d8bae53a90ae8fafcfe41e07259123a987fd75feff994a56e9d3da75eca4212cbc209235a6a1f920867cbeec5d3c142a8e16abd5cac279a9ae595f2115c58e5c12d608bcbaad94c4fd9256800dc3c26b }

condition:
	$a0
}

        
