rule Win_Trojan__0657_0002_000_1
{
strings:
	$a0 = { a4082e8b96a608cd79e82000c350b440cd793bc17401f958c32e8f868c085053515257561e06 }

condition:
	$a0
}

        
