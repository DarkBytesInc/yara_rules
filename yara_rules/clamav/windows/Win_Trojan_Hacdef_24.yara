rule Win_Trojan_Hacdef_24
{
strings:
	$a0 = { 2461a4e77ccfe788456246c46c605b503e0ae63cd1759051efdff99aab9b8b8351f5c327fe54ada22dcf28566c5297fd4a591d9212da64e3b87fe2e9f19e3d588c71c7ee95c24c12a10cf613265fae4e3c6abb6a6866d8f9b91c6282 }

condition:
	$a0
}

        
