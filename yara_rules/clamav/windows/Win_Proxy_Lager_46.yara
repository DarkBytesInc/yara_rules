rule Win_Proxy_Lager_46
{
strings:
	$a0 = { 4aa1d80bb3debb5bfe9bbd741128370d9e444e1b8bdf8c2b002dedeec209bc63c60fb5ed8291599ee4946bb5cdc0935bfd05a029b6f1c9be20717b2b8ad48382ce63ba573010 }

condition:
	$a0
}

        
