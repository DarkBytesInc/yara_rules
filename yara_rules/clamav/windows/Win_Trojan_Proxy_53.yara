rule Win_Trojan_Proxy_53
{
strings:
	$a0 = { 7a90a805a8c39fb21bec51c929349ef7f8cd8be6847ab00cb5e73fb6afd5cb6947a3ea8a3e97a9277f6a4bba005766f90ea513b2dd296778e087c5540ad384d314eb37058b9ae5d9e73e103b70f2d3aadc4b7f6439d696aaaf890a1236a2d45c68a2c153 }

condition:
	$a0
}

        
