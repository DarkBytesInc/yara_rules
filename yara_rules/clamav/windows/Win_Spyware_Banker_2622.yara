rule Win_Spyware_Banker_2622
{
strings:
	$a0 = { e6cf096ace9031a8af58ed3aff9562a9b107254747bd1838f330f0af197bdb4310f254c0b259f56b146b27c3d46f7e2635336f1f783f506e3ee1fcb7b8b28ad3ac876a3fd003de5a35efdbd2989da637342b59b05cf3c1ed5080e21c58bcd0d2dc063aa7f9815498174c2d2d373d1f9ef07002682729321a8a974113d170c799bf9271d88908 }

condition:
	$a0
}

        