rule Win_Worm_Cazinat_1
{
strings:
	$a0 = { ba082d40008d8ffc000000ff158c11400068342d400068b02d4000ff154c1040008bd08d4d84ffd65068bc2d4000ff154c104000 }

condition:
	$a0
}

        
