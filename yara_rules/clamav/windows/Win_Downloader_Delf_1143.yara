rule Win_Downloader_Delf_1143
{
strings:
	$a0 = { 87b8f13138b5a04e41c223c642bc77bbf3e196d82abef42125eb57d87a006016f850675257b841e63a5a63f69cf179525974acac3a4d9fca78accfca9576206866188edf1b6ad861a29aa4d0b82ff6a09d }

condition:
	$a0
}

        
