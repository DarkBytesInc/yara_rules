rule Win_Downloader_Banload_466
{
strings:
	$a0 = { 866e5c59e305447b055f5f8901e80e976b458892170ca9493f1cbbcd0d3f4c26bdeb8b227d799bc6397b7577c180a3d4b8fb9f073e9d59b6798b157cbf85b7aacbe69d3accbdc81da16166bee39ff5a745f6bf3d }

condition:
	$a0
}

        
