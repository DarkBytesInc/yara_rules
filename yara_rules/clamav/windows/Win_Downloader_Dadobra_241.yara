rule Win_Downloader_Dadobra_241
{
strings:
	$a0 = { a6973a84b70bf4fb4a5d34b5040582bf47ded1ce4653d16a510c9d464eeeb551466f0d96bdf9ec840fbffcc045668fe1cbcb807fe93623873d6dad83c36c15b20c3e789e5343f196da98d2e0d89a06e8ae910a0142 }

condition:
	$a0
}

        
