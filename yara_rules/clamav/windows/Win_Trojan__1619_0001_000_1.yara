rule Win_Trojan__1619_0001_000_1
{
strings:
	$a0 = { c0b44233c999cd21b440b91001ba0001cd21b43ecd21cd206d616b696e672056697255437449 }

condition:
	$a0
}

        
