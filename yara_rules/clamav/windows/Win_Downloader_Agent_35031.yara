rule Win_Downloader_Agent_35031
{
strings:
	$a0 = { 2934a9ab56e515df75a8ef547ffba98feff7f2a459e5b2954791b4e8d7de72b99fe5f6a4fbe6b55247bdb6ec882a6654a0e54d6ea569c1ac8d06fe6b47b20aa604b4b48b7bf8a9c455be8617a8a2b38b6fa8f807efffa9c95de5f360f250 }

condition:
	$a0
}

        
