rule Win_Downloader_Delf_916
{
strings:
	$a0 = { d1c78eead8fc3ba6e8998521c346e2cd8239d07d6570479cf969d7c8cc0b17b27fa9dbe9a8177f9ace1d3fa1ad0b489b383b56655156ecb2e25bfa796ccf19f9d9795c776ac962d5787a00d04d71fd5fea99b26a8110ff80f33e2bea929639f791d2becc }

condition:
	$a0
}

        
