rule Win_Trojan__0773_0001_001_1
{
strings:
	$a0 = { b800429933c9cd218d960f04b90400b440cd21e81200ba8000b41acd21b800015033c0c3574859 }

condition:
	$a0
}

        
