rule Win_Trojan_IRCBot_804
{
strings:
	$a0 = { 6a3072692e7230782e75722e7730726c64000000494d7c6c306c002e2577696e64697225 }

condition:
	$a0
}

        
