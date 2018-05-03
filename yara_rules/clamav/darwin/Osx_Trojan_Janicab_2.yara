rule Osx_Trojan_Janicab_2
{
strings:
	$a0 = { 7375626a6563742e4f55[10]355832484c3653353458 }

condition:
	$a0
}

        
