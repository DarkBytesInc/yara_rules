rule Win_Downloader_Banload_964
{
strings:
	$a0 = { 7658e67858c121b976d4b2f4a1ffa147cb4f7a704ee3b49c9f9379c2862abd89fc4f1f97d88ada39a457ae3f84a073ec4ff1058feb1af073195e7fe3c95c2ed849d0fc43cf72c4dbb576126e859ed636b6e25e508daa1dedae72b42fb42dba48bb26f3c8a232b50b4c76884541e3 }

condition:
	$a0
}

        
