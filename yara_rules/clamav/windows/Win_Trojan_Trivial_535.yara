rule Win_Trojan_Trivial_535
{
strings:
	$a0 = { b44e41cd21ba????b43ccd2193b4405acd21c3 }

condition:
	$a0
}

        