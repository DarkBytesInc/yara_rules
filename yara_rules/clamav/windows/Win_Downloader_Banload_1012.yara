rule Win_Downloader_Banload_1012
{
strings:
	$a0 = { a66a3de679aba80b50d7fe40e29b3c7ababcf046582b6fb98ecca9ef521b39aada0958c404a3d2c34baf67f259f53d05e0160b1a8368eaf0e8faeb282ded69f8e44aa70e4668f86cd821accdde1097593b9af53bdafc8ae4357d83a35c24322d4c274638091d2781ec1fbd95318c1c7d }

condition:
	$a0
}

        
