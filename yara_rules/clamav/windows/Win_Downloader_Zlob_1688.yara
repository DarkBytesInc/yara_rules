rule Win_Downloader_Zlob_1688
{
strings:
	$a0 = { 0309a2dd9dd9726438f218d8d75dbf40bd26b4c149a96e1863351ca6a7c72c61b51b85a966f3a5f95905ec731b3df0e0f445f3793610263936bddc4aa79b65606a6da6f0f2d918fdd53d3399f803fff3b23f3b8c4e1c0e4ca7cc }

condition:
	$a0
}

        
