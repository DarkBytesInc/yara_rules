rule Win_Downloader_Banload_719
{
strings:
	$a0 = { 5ba34a3316ca898b3dea4e8006ff23b9835d6027965465a04fc8ebc178e5827a428e667120ed0f5f50a6ef924a8d204a88c4e31a337b3bca8378fe6ee122e9fbaadbb9731b4b1b06ac0c1fed5e46d899c48250d494ac7e1e3bec }

condition:
	$a0
}

        
