rule Win_Spyware_Banker_2429
{
strings:
	$a0 = { b60f4ebb98b734dccd025426062307920a18de341a36b5ef11b7e3f473efc0ed4e230efcfec94b940bca80f6cb404a7ecf9e5279359aaaac197bd66c6901e4f1f6a519a4fdc8e1b9e1eaaac54226cf5e2099f89d0f5ff26f353b3d31baaec1fde71eb796cfa5 }

condition:
	$a0
}

        
