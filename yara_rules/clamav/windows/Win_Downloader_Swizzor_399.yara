rule Win_Downloader_Swizzor_399
{
strings:
	$a0 = { 24d58b815b7a440fb0a1a4ce8166633208d76ba934dc53b78d160c540dc795d8ac2b7e866657d5b533ec1d00c209ba881e9d6c41bb4b9a52327ad7c67531fc3423ded3dc3bf5f3acd50daa56de6a2eaafb2e268ebd5f62fa71ea }

condition:
	$a0
}

        
