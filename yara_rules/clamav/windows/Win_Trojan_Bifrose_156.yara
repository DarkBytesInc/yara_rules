rule Win_Trojan_Bifrose_156
{
strings:
	$a0 = { 3862f242977d00b4551620f8e9185800de32d694d16b52741d3db9b2c05e200bf159ea00040968d72372daeb00f088c3e4e0e8dcbf00592594ed8b1756d9f291e8bd0ff7 }

condition:
	$a0
}

        
