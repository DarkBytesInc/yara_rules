rule Win_Downloader_795_1
{
strings:
	$a0 = { 2e080c202874cbb2fc372cff5ca1a0284a0b3a88d361c82622baee906e7c63422e0830b1d40a5a10e929d0e3df7b9fadc490b22bf3b62b5a6e07003429a6e9050dc406a8ceecfd08ed8f33119d049573a35480b899a63a6529e19f1d4d771601d649e22fd73ff35bd36d840e0e987b26c2ee80f653ba0d4767d4fdb5 }

condition:
	$a0
}

        