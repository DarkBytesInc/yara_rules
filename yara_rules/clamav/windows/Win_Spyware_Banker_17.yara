rule Win_Spyware_Banker_17
{
strings:
	$a0 = { 35b1f5dab604aea47fca51753a754e7155a3d31172b727f4b8b6a12c5d98e17a0d2ea3bd5333fa19c5b8c9fb457442a7f538bfd22dae2fc13b5d1f5de425a4b39928baac47e9cfeb5b982efc46a12e62b7e94ffb9e546a74b5ba72ccfea55bad3ebb55a3f6b15d }

condition:
	$a0
}

        
