rule Win_Downloader_Delf_1979
{
strings:
	$a0 = { ff12098a0156c5a0bc423a056c9964e5bebd4b12a381a1088900dbb450d8c30ac28633640200830ac3002097ee5400fbb35c027580c55c9d080aa08581995c896d04c425b2124ae021980f423139add8a754d31d5b5658271af0078719356b73f3226284da32f890092252b62555d8b066e5b02c28cb1c187003037531a383993b6b9f2049a28d504c8f4dc1 }

condition:
	$a0
}

        