rule Win_Trojan_Keylogger_176
{
strings:
	$a0 = { 5379735f6b6c5f756e696e7374616c6c00556e5379735f4b65796c6f67000050726f796563746f31 }

condition:
	$a0
}

        
