rule Win_Trojan_Bancos_1050
{
strings:
	$a0 = { 1fb87ef9854f6d4c8a0d5d6a7ab28a0d5ca4cc1425d28d22fa97d508452b215708829c322705df4ea2b9a15e2319dbbbc1d0e58de7853e7614fae1173e7ec6c282aa651686a1b7f172fef91bd6271c7f68befca460 }

condition:
	$a0
}

        
