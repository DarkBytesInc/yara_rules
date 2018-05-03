rule Osx_Trojan_MSShellcode_49
{
strings:
	$a0 = { 31c05068ff02115c89e7506a016a026a10b061cd805750506a6858cd808947ecb06acd80b01ecd8050506a5a58cd80ff4fe479f650682f2f7368682f62696e89 }

condition:
	$a0
}

        
