rule Win_Trojan_Small_3763
{
strings:
	$a0 = { 3fbce06c00d536e813fd303fa6bd335124d020e990a452ec3bbc63ad54bb550d54bbf6f14bfce0489a193c42ff1238513ccce0e9a5c4dffe73cc20e98bbbf6254cfce0742c27e1535f124be93ad234f97bbc65a9b0ee6b266ccc20e991bbb86efc30063f3b9461656cbb3d5e4412e0c0bc2011 }

condition:
	$a0
}

        
