rule Win_Trojan__1304_0006_001_1
{
strings:
	$a0 = { 723226894515e82c01bafb06b91c00b440cd2126c745150000ba9a06b440cd21268b4d0d268b55 }

condition:
	$a0
}

        
