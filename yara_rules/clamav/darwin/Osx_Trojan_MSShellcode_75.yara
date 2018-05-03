rule Osx_Trojan_MSShellcode_75
{
strings:
	$a0 = { 4831ff574889e66a045a488d4afe4d31c04d31c948ffcf48ffc7b81d0000020f05813c244e454d4f75ed4831c9b81d0000020f05b85a0000024831f60f05b85a }

condition:
	$a0
}

        
