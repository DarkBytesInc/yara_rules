rule Osx_Trojan_MSShellcode_73
{
strings:
	$a0 = { 4831d2e809000000[0-10]005f52574889e648c7c03b0000020f05 }

condition:
	$a0
}

        
