rule Win_Downloader_1379_1
{
strings:
	$a0 = { c511433c8eeead6bba121e1a9a666a16434853d3bdffa9c02e9765ccc32d77baf9842fe0e6b53d689aee48bcb5e96614729b4eb73d693cc4ce9428bcb79c2c3c6996a30108ce5fb4d9938e65d9e2fe7591ba1e9fddd9f0ee31b2331d00fe6162fcb62fe68834 }

condition:
	$a0
}

        
