rule Win_Trojan__0655_0002_000_1
{
strings:
	$a0 = { 8b048dbe0e010305508bd4b440b90200cd2146465859e2e7b80042b90000ba0000cd218d9637 }

condition:
	$a0
}

        
