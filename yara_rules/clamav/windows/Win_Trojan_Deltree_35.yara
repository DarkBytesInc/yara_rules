rule Win_Trojan_Deltree_35
{
strings:
	$a0 = { 627265616b206f66662064656c747265652f7920633a5c2064656c747265652f7920643a5c }

condition:
	$a0
}

        
