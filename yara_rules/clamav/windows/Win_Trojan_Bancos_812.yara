rule Win_Trojan_Bancos_812
{
strings:
	$a0 = { 3b05f114747f134fcaef83cb18b10aa597d131ffc8d3d0a5d89e10dcd6383b929bacb2b70e42d1d2b8edf749a7dce330cb0ed061ec8ae8fec203a2e29df06b471875f45365bb2aefb70ba2c0640fdfbcc8dc3c274a0fc39f54c4649b1559b7fbb608f0922949c21d }

condition:
	$a0
}

        
