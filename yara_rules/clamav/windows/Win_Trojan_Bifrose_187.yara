rule Win_Trojan_Bifrose_187
{
strings:
	$a0 = { 1fe0050a0014b6a73fa5ef01d654b10cbf53023fb0e2fa006c01b8f117845bc7f4cb00eb8565b735c5f3fb00d78c441e0fe83130f00b015a09d5250417df606659077896 }

condition:
	$a0
}

        
