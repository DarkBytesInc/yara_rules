rule Win_Worm_Mytob_372
{
strings:
	$a0 = { 2ee63812c7067dd56683e0ce5c764580bbbe97eb00a262439c666235cd90108fbecc2e494f4ce3aaa335d21354c94810638b469ecb0b1c60a28b764572212471e05caed26886211964b436784328c609ee7b3a4f182a1781dd48bebd8b9fddf2fa21de6b1af6166dc3f575f08796694bb7cdca3b39bb0df3b6978d6f18a0317133f4e44dd08eca21d31c945fe622c17a4cef51ff6c16 }

condition:
	$a0
}

        