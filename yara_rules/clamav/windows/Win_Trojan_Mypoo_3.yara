rule Win_Trojan_Mypoo_3
{
strings:
	$a0 = { 3a0000ffffffff1e00000052386d7970303020426f742076312e30202863292053686170654c6553530000ffff }

condition:
	$a0
}

        
