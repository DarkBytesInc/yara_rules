rule Win_Trojan_Viros_1
{
strings:
	$a0 = { 1fe800005e83ee09bf0000bd00685507b9ad01268b053904742356f3a433c08ed8a184008b1e860026a310012689 }

condition:
	$a0
}

        
