rule Win_Trojan_Small_3744
{
strings:
	$a0 = { 0068f65b92280ed63b67a66d103be6057d0f2e09282729ca407da5dd6877fc6f297a0eee3b67a65a1099a90528aa6a1e279cca1d273dae15682705648582ffc87e7e0e063827a66f3026bb3d3867a655273de215682731f6922710297e91a6043e7bb64528ac667a5ab2e3353867a65b27ff2b }

condition:
	$a0
}

        