rule Win_Trojan_SdBot_3862
{
strings:
	$a0 = { ea3bb1763698b1e1eeb920f4b9686a94e629925b391f5bef6a89f1677ab0c611dcd2ed3777a7062559753dc5fa359d4d84cddff6ab056b1c01cf068df11520fc2650681e55fdc2d2ffe5a0c7146c64e8ac9d09221f }

condition:
	$a0
}

        
