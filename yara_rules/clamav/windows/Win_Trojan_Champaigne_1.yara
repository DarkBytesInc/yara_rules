rule Win_Trojan_Champaigne_1
{
strings:
	$a0 = { 81ed0701e83402b42acd213e889636033e88b635033e888634033c00740abf00018db69e0257a5a58d965603e81101 }

condition:
	$a0
}

        
