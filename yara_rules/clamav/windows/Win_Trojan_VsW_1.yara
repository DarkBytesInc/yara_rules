rule Win_Trojan_VsW_1
{
strings:
	$a0 = { 6f762064782c383068202f20496e742031336820bf02001e57b8200050bf5c091e579a2700 }

condition:
	$a0
}

        
