rule Win_Spyware_550_2
{
strings:
	$a0 = { c609b900fac7100101b2dd0ff3eb2cb0718097c137175380159c14b9eb4843558436f2ed3d0301929e3ba4791a5a1e05a3eef61d6a3dbe6b26edf59d5d20f8dead96adb674858e6042d5451fe1ee }

condition:
	$a0
}

        
