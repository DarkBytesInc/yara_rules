rule Win_Downloader_Banload_1025
{
strings:
	$a0 = { bab2b1f4bfd2616e9b7187cc9f9c1528c6a6cc86d24ae98a4c9090005bbd69efe07803ff4c8df281045493bd944cca26f250cbe06fdf7ad113ae511bd5f01a694cbd6fbfd529473cefaef4ac57c9a967debbd819834b8acaaf1d465a04d0e5526350a6c24069aefb98c2875e7c }

condition:
	$a0
}

        
