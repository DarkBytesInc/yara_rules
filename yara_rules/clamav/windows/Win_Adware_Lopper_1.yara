rule Win_Adware_Lopper_1
{
strings:
	$a0 = { 5f5781c7dc0c0a0083c7438bdf83eb2eb91508000033c08a1732141888174083f8057c0233c047e2eece1d5173f87a49c5d9212914449d }

condition:
	$a0
}

        
