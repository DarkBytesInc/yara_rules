rule Osx_Trojan_MSShellcode_50
{
strings:
	$a0 = { 31c05089e76a105457505058584050506a1f58cd8066817f0225b775ee506a5a58cd80ff4ff079f6682f2f7368682f62696e89e35054545350b03bcd80 }

condition:
	$a0
}

        