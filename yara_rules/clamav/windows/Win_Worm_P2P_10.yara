rule Win_Worm_P2P_10
{
strings:
	$a0 = { 706f726e2e65786520633a5c70726f6772617e315c6b617a61616c7e315c6d7973686172 }

condition:
	$a0
}

        
