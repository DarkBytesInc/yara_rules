rule Win_Downloader_Zlob_1693
{
strings:
	$a0 = { 5e2c88fcad149431ac09b5c1463ffda8a04c1cf8d75611efb0f3a84965f806f5a0fc427c11c883a13a984791145f4df64e2be7bed8f0b6ec7abf2d5aba429cc2ba59a24c6658022789ab68a520aebf46889b5b20db51cb928399 }

condition:
	$a0
}

        
