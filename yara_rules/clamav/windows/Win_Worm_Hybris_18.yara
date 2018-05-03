rule Win_Worm_Hybris_18
{
strings:
	$a0 = { 9fae47debe7114510568ad25255df78522042cfc5dd65cf49bf63040341d8eb3601a17047e36a91f1992c210eb3e0a49a0020cf7f767dae53fc56671c4b8832f }

condition:
	$a0
}

        
