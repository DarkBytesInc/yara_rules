rule Win_Downloader_Banload_940
{
strings:
	$a0 = { 4f4b9797c1f873ee9a6f30a1d0edfa7f4668902c13d1eaabfb16e90cfcaae915ca573661058cd85e833ca6a80a68553f4f8d0a57db827c4b6824331e6dc57a910b6db312ccc1790b185b93b49f61a14eb9ec0c9a302e0a8ca0cb58f4a69ee0a654224a2cfdeb58a1f8146367 }

condition:
	$a0
}

        
