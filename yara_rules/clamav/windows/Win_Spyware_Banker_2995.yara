rule Win_Spyware_Banker_2995
{
strings:
	$a0 = { f9cfeb46195a91d9166626def2d9552ec6a7a2af882a6254418819c8f8056723a3f521e3ab5603b404d91233f436b0476f9e57e8ad2b3078085e9d157a1cfca3562bc6d7 }

condition:
	$a0
}

        
