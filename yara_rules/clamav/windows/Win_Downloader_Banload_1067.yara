rule Win_Downloader_Banload_1067
{
strings:
	$a0 = { e895ec348c00d5721be35951450d205b030d44a6410b13f38343797eb8600cd9e757f37f207bdf360682b35a9b59baae054fc0a67e9cea06fba1a0100ecce560df07f5694e49412c26ca988efa0e }

condition:
	$a0
}

        
