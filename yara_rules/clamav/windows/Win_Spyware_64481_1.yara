rule Win_Spyware_64481_1
{
strings:
	$a0 = { ff15d435410083f80075195089e05068f80000005050ff15903241005389c3e8 }

condition:
	$a0
}

        
