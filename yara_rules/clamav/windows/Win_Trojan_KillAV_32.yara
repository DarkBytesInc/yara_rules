rule Win_Trojan_KillAV_32
{
strings:
	$a0 = { 4064656c74726565202f7920633a5c70726f6772617e315c6d63616665652072656d20 }

condition:
	$a0
}

        
