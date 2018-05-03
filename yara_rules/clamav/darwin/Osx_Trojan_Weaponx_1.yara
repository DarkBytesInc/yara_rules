rule Osx_Trojan_Weaponx_1
{
strings:
	$a0 = { 0c5b20776561706f6e5820[0-100]726f6f74207368656c6c2e[0-100]75696420746f20302e }
	$a1 = { 7569643d30 }

condition:
	$a0 and $a1
}

        
