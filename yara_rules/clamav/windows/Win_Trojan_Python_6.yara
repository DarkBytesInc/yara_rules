rule Win_Trojan_Python_6
{
strings:
	$a0 = { 66696e64282723736f6c61726f696427[0-20]6e69745f5f2e707927293a20663d6f70656e28686f7374 }

condition:
	$a0
}

        
