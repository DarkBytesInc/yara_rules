rule Win_Spyware_Banker_4400
{
strings:
	$a0 = { 0156c5a0bc423a056c9964e5bebd4b12a381a1088900dbb450d8c30ac28633640200830ac3002097ee5400fbb35c027580c5f49d080ae88c859c104640106810f097002c74930f4a9c23add8a754d31d5b5658271af0078719356b73f3226284da32f890092252b62555d8b066e5b02c28cb1c187003037531a383993b6b9f2049a298964e8f70148c0b5c6a }

condition:
	$a0
}

        