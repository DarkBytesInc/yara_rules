rule Win_Trojan_Crypt_117
{
strings:
	$a0 = { 60e8000000005d81ed16d44100b988df410081e9a3d441008bd581c2a3d441008d3a8bf733c0e80400000090eb01 }

condition:
	$a0
}

        
