rule Win_Trojan_KillAV_20
{
strings:
	$a0 = { 6563686f204d61696c2e746f3d6f6c2e4765744e616d65537061636528224d41504922292e416464726573734c697374732831292e41646472657373456e7472696573287829203e3e20433a5c6f6770796f2e766273 }

condition:
	$a0
}

        