rule Win_Downloader_Banload_378
{
strings:
	$a0 = { 26afb510563b93ebcb783a959c9a1404c4d857915c21d41adb57ac17e0aac96a3338ca31e6d06ecfd17bb4cf58b6c82a6a20bdcdd468d49f40cbb29289de8682859cbfaba51e0542369dc2a6315f555ce97beaf6c7715c8cac865ea72b32e06c787645f4b6c6bcf700 }

condition:
	$a0
}

        
