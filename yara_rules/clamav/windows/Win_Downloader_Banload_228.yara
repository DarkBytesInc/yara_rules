rule Win_Downloader_Banload_228
{
strings:
	$a0 = { 2cc89dfb561517ebc2e6ac88d18b77328f4a4b41ba6360d9ddef391500c067527c67785463756a5d7d6d686f4c7046ae3f22d430cb88f44e028ce69936eb2a9bb779694d93c71aa5996993cf2687a94db9e4b0c96361a93d99a669f2d985e92df9e534796c9ae9f19981d3344dd3a9b1b941a94dd3344da59991690d79924cd33405699599e181699aa669a965b99da9d32499a69199 }

condition:
	$a0
}

        