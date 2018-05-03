rule Html_Trojan_VBSShutdown_1
{
strings:
	$a0 = { 636d64202f6b2073687574646f776e202d73202d74203232 }
	$a1 = { 633a5c747769737465645f6d696e64732e747874 }

condition:
	$a0 and $a1
}

        
