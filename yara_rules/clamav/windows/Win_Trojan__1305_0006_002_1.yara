rule Win_Trojan__1305_0006_002_1
{
strings:
	$a0 = { 723526894515e82f01ba6707b91c00b440cd2126c745150000baee06b440b91600cd21268b4d0d }

condition:
	$a0
}

        
