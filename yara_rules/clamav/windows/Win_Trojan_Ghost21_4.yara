rule Win_Trojan_Ghost21_4
{
strings:
	$a0 = { 6e73756c74000d01260057656c636f6d6520746f2074686520616d617a696e6720696e73756c74206d616368696e65210003 }

condition:
	$a0
}

        