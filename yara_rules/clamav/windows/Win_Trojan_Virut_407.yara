rule Win_Trojan_Virut_407
{
strings:
	$a0 = { 52746c496e6974416e7369537472696e67[6]53654465627567[13]6e6b6e6f776e007262 }

condition:
	$a0
}

        
