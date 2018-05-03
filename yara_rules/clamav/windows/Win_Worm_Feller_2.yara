rule Win_Worm_Feller_2
{
strings:
	$a0 = { e8b8dcffff68b4684000ff75f0ff75ecff75e868e46840008d85acfdffffba05000000e8c9d2ffff8b85acfdffff8d55f8e887dcffff68b4684000ff75f0ff75ecff75e868fc6840008d85a8fdffffba05000000e898d2ffff }

condition:
	$a0
}

        
