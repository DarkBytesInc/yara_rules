rule Win_Worm_Mytob_311
{
strings:
	$a0 = { 6d6c3e200d0a00004e65787450617274000000002d2d2d2d3d5f25735f252e33755f252e34755f252e38582e252e3858000000005365627a3a2000000d0a47623a2000000d0a46686f777270673a20000d0a516e67723a20000000000d0a5a565a522d497265667662613a20312e30000d0a506261677261672d476c63723a20 }

condition:
	$a0
}

        