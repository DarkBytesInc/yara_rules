rule Win_Trojan_VGEN_645
{
strings:
	$a0 = { 0646b800100501eaba4559b311cd21e800005d81ed13000bf67461e88c002ec686390300b42acd2180fa0375062ec6 }

condition:
	$a0
}

        
