rule Win_Downloader_Banload_1101
{
strings:
	$a0 = { 7fea36719f379664b8be8673edb55a864818f28d0d59ddedc6d016917cff2550c614afb48bfc848d01c45a839663da750185dd65f9614b3a929e883354e375d3c56a6c65e92bb7 }

condition:
	$a0
}

        
