rule Win_Downloader_Small_3433
{
strings:
	$a0 = { f4f7a7e106ce4eb3bd8b012e7a599ba903a7d8417663d581264334e2077ff74c5f8318f97ca41b411cee4fff36280a5cf733d0526162374bcca1fcaa64a98a87e184ed7e1f436810c205a665dc5df41d46bab20682 }

condition:
	$a0
}

        
