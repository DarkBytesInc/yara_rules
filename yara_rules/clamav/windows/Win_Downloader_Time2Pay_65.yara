rule Win_Downloader_Time2Pay_65
{
strings:
	$a0 = { 733ea1ff87830e6552dc3f7577e92f6964d0316577dc0bb0ef46a28b629d55579b47dec9ef8a9d33c04bf3f7c1f029156ebd6fba03cea27f7afb4f3bc1cbb65f4c7a088bfa38b1bc15f70b8d550a81b6ef750a33cbe9d45dea7f54ae1374e7ce7d2f9665df0f8d80c1cc8fd3ae55e766a9be89a8c56f46d71361f5 }

condition:
	$a0
}

        
