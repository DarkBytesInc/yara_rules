rule Html_Trojan_Fakesec_12
{
strings:
	$a0 = { 7372633d226368726f6d653a2f2f616e746976697232302f }

condition:
	$a0
}

        
