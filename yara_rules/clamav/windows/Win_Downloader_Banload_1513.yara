rule Win_Downloader_Banload_1513
{
strings:
	$a0 = { 4ac2e35ec448d68585701dc2b7e6527605d79fc0f1dd61bd44a3fdea6b535c0ccf892552fb5178ee870aa6ea292bbcb3a0d775e04a832afc582f4c8b9d590c7abde6cd1137cf164a636bbfcd94acb73904d163b4e76ed078b37bbaeebfed2be13a1daaf66d55d72bcfd8c903c71f3c333623b6d1028b }

condition:
	$a0
}

        
