rule Win_Downloader_Small_4795
{
strings:
	$a0 = { 58044279808e5bcf6c04576f7264a0f36c5a03ff80084361afc53ae1696e05e0b5109c90980a065374c065c15a7267a40b0a57696403f7f85965fcc58fbed304b833e7392c96c4c8ccc0f3389ec020313c7807544f626a14739705656374081121981cb879737e8b43186d28ce80d0110f0a497266616365b268b855c030f276314603a86401a0cc83442404 }

condition:
	$a0
}

        