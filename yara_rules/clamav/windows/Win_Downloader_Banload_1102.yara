rule Win_Downloader_Banload_1102
{
strings:
	$a0 = { f48d0d59ddedc6d016937ef12b50c614afaa95fe868d01c45a859461dc750185dd63ff6349248c9e883354e17bd3c56a6c63ef15b533f80f42950f08fc97a763c8403792047f19 }

condition:
	$a0
}

        
