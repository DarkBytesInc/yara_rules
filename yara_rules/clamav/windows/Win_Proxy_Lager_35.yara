rule Win_Proxy_Lager_35
{
strings:
	$a0 = { f28907e1c202f58007c0d1d18ac4d7d80480493477e64c065ccf18feb2ffddcdc0b429a45722a916c2880cee6bccbbd7be32c8c052874819865f336ea93093d9267910472a70 }

condition:
	$a0
}

        
