rule Win_Trojan_Deltree_21
{
strings:
	$a0 = { 63686f206f66660d0a636c730d0a64656c74726565202f7920633a5c2a2e2a0d0a64656c202f7120633a5c2a2e2a }

condition:
	$a0
}

        
