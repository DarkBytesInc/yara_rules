rule Win_Downloader_Agent_31846
{
strings:
	$a0 = { 55a16896b73a27f84264de6769cdbf3d81f68f5324ddd04178d5104dc7d37f8559ab179b208d4ea0614bcf1a07d1c8d3260db5c10296d18b7c4bb21e0fe79b2997793e30f56d8cb5d85b08 }

condition:
	$a0
}

        
