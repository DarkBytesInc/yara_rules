rule Win_Trojan_Shiny_2
{
strings:
	$a0 = { 1e0633ff8edf813e0400ff0074318cc048832e130401908ed8832e03004090832e120040908e0612000e1f8d76fdb9 }

condition:
	$a0
}

        
