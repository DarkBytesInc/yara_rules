rule Win_Trojan_Prorat_76
{
strings:
	$a0 = { 49a2b97ed0de229d2db4ecdeb099cc4f3b613e4246db675061c87547c3fa03c2d1d6dfc57f4808a6278504ecab0f67f43cab8fc5e4e2a4ede5dbea6d3042b59bf7cc9c1f0b34247eb0c6676b28e8f4e703848e4d2156f1993c04c37dfcdd42c42e1fa62ec0cf40cc0df5209ae433e967bdf58be1f006747239a5fd }

condition:
	$a0
}

        
