rule Win_Trojan_Pigeon_23
{
strings:
	$a0 = { a3bd0f5c9455ba38fece1f60c05146c5bf69528da5020a62a502db288ce11f7414515048dd7042b3e4cafbaa25e8b0afecf2729c5dead66ef766776575efedb6defd52ba89e4d6c8107fca2d443731ad28adb097da49591d959cdff39c73de61fcb35a9f9f1f799ff3f739e73ce739cf79ce73fe8cd1220851e1d9e286 }

condition:
	$a0
}

        
