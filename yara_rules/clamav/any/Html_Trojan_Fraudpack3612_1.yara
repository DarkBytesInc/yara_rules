rule Html_Trojan_Fraudpack3612_1
{
strings:
	$a0 = { 558bec83ec20ff1514814200ff15a08042008985e4ffffff6a00ff15e88042006a00ff1514 }

condition:
	$a0
}

        
