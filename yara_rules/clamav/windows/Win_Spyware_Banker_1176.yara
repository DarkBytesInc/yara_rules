rule Win_Spyware_Banker_1176
{
strings:
	$a0 = { 91746d5b5d2050a5a20b58d468dfe7a6a377adb9679899c40f44f52bacf0c4ea6f3b1b1b1bbfaa6948fdd38ceb494cf3f3d59f7b92fe50e62661b9cd2dad2631e8182e2299cfc9e2220429e013d7d5f48951dc20aa66ef0e7fe2 }

condition:
	$a0
}

        
