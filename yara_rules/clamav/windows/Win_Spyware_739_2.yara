rule Win_Spyware_739_2
{
strings:
	$a0 = { d2aae422d13800e29e3f2a8ab3d7f0ba829943395506da1c307d7ff5fb8d086a1e45a07d263dab37c57e10224b7af0ffe4dd82f0d43e5e4a3d5cd76dd5d3dcd817ec2c915e33a3fee1204b180caafb8d0c2543f7dfd96827b317 }

condition:
	$a0
}

        
