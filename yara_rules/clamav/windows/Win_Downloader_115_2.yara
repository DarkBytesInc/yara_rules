rule Win_Downloader_115_2
{
strings:
	$a0 = { d73092e4ed7a9a25d83f4a5aa8480f0ed5ba8936d73096e4eda29a25d83f4a5a9482cfe1d9ba8ae562008645361653a92d467667c4fb93e5d70de03c0b96431ddaba8a18984847a7ceba896e757b80e5d7ae }

condition:
	$a0
}

        
