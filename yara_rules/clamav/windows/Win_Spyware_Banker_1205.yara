rule Win_Spyware_Banker_1205
{
strings:
	$a0 = { e980405fd1798cea83d5fb182ecaa51ddb05cf698b5a1acde1d093dbf4542a2dab37d37d9bfe88550008e9869548e26202112aca0a0a72450ed9695bafe21456080e564a3c3444eae127dd39ad1c2971193bfae41a2192aea132 }

condition:
	$a0
}

        
