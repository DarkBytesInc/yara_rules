rule Win_Downloader_1323_1
{
strings:
	$a0 = { 30d0cdd2c0af29afe2cb0cb279af231dfdfcf95db86d84d90277ec397dc5312b15471b6e8b3b481eb34b6ae8f9cfecf9d5cda32d0403d9b697901957a29b6b4b3fe5c6cba448cb34eca1fc04d89406b67cd4a1e78fbb06d1b3f219e87f62e6ac4fa2 }

condition:
	$a0
}

        
