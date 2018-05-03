rule Xls_Trojan_Umop_1
{
strings:
	$a0 = { 756d6f702061702173646e2d4f306f2e }
	$a1 = { 2e5374617274757050617468202620225c426f6f6b312e786c7322 }

condition:
	$a0 and $a1
}

        
