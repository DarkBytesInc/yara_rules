rule Win_Downloader_1077_1
{
strings:
	$a0 = { 2d49ab18b113420cdd809e3a10c8b5158d554e4e08b51ff3410bfb9c160e093628f9a0cb7e1bb41179461b5a8acd58c148d55cc95fcc5d980d3ed5c28feaf95d2a2f68e247aacd396af69bb93d72a3c43bc0f6cbb6258dc7f6839ba5 }

condition:
	$a0
}

        
