rule Win_Trojan_Small_3787
{
strings:
	$a0 = { 1cdbbffb6c8c6a13494f77968c9f55d9f94a562551509657eaa2ba68aeff6a13c6e3c37dc7e2c97123e62d685177bc6419e1c19e4393ed78ce8af55a028e31227dd370988f14b80f45caf7c3ce8b }

condition:
	$a0
}

        
