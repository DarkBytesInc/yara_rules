rule Win_Trojan_Rootkit_37
{
strings:
	$a0 = { 568b742408576a0abf000301005933c0f3a674128b74240c6a0abf0c0301005933c0f3a6750333c0405f5ec20400 }

condition:
	$a0
}

        
