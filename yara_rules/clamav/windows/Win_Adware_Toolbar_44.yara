rule Win_Adware_Toolbar_44
{
strings:
	$a0 = { e805000000e917000000518d442403b9286c08105068e0e20710e8fae2fdff59c36867870410e8e58b000059c3 }

condition:
	$a0
}

        
