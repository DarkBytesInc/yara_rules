rule Win_Trojan_Deltree_31
{
strings:
	$a0 = { 406563686f206f66662040627265616b206f66662064656c747265652f633a20795c2a2e2a }

condition:
	$a0
}

        
