rule Win_Downloader_Banload_1319
{
strings:
	$a0 = { 94b44c5a6c713852ba3bae2a69c39f938c0b4b4448f4376f3f5b7f1872fcb348affcddddc15942136e2102f542c23bbf2ad6d375f7feaf9e95b6504aec429eef090b864d9ca540deddd2eedc81e645f6df8e8b67474a7267307703681fddcb9e376ce4eb25baa1021aae5cd2f68dd15b4cb6961c47eb2b69 }

condition:
	$a0
}

        
