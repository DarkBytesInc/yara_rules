rule Win_Downloader_Banload_965
{
strings:
	$a0 = { ad92a8e86922fc661e4e7b748f08b338d8dc5fc8ae470fc7fa547e62a666d3c9760149b4ab3182eb6be0ececcbcf85145f951c5096eadc4ae2d66fb7a96c9e8b3fd36d29dd116cefa1b42801e6b8b4ac2e29c35203b5031580fd55929eb9f0a85df3a809df1d86c66b72630255c8 }

condition:
	$a0
}

        
