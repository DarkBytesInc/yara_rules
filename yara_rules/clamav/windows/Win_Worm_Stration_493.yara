rule Win_Worm_Stration_493
{
strings:
	$a0 = { ad794e6994dd7d17413a2a20546212c016b7a97772e9add60ccb46032619c4494e7672792079130ca83f21e6cba373a832ee49205a27b7d86ae43fd66f37bbdb502f724f5e3c }

condition:
	$a0
}

        
