rule Win_Trojan_Small_4625
{
strings:
	$a0 = { 583a5c6175746f72756e2e696e66[0-2]583a5c72657379636c65645c626f6f742e636f6d[0-164]504f5354 }

condition:
	$a0
}

        
