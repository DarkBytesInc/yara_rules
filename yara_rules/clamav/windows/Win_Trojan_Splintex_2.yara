rule Win_Trojan_Splintex_2
{
strings:
	$a0 = { fcbf3ffcad426bf9800ca93e7bfe97df3fcd775f7aa4f9ffaed55c23377ec002bbbe549f3753ffe4e1febb6001d5d2a4f9bbd57c7f3d55f7cc5f5572ccd7f6a93e7ffbd801607c21f572a4f9baabeab75f7a8454c226626172 }

condition:
	$a0
}

        
