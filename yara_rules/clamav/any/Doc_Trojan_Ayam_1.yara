rule Doc_Trojan_Ayam_1
{
strings:
	$a0 = { 49662053797374656d2e5072697661746550726f66696c65537472696e672822222c2022484b45595f4c4f43414c5f4d414348494e455c536f6674776172655c222c20225739374d2e4d6179612229203c3e202250617220506574694b22205468656e }

condition:
	$a0
}

        