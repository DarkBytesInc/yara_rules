rule Win_Trojan_IRC_Script_52
{
strings:
	$a0 = { 5b7266696c65735d0d0a6e303d72656d6f74652e696e690d0a6e313d5758666469736b2e646c6c0d0a6e323d575a6972646c2e646c6c }

condition:
	$a0
}

        
