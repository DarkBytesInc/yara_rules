rule Win_Trojan_Splash_1
{
strings:
	$a0 = { 61740000ffffffff0e0000003a5c77696e73746172742e62617400004d61696c546f3a6c616d65724076323030302e6f }

condition:
	$a0
}

        
