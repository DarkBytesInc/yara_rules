rule Win_Downloader_1040_1
{
strings:
	$a0 = { e8a4d9c5c3fc25cba94b251be44ca4e85dd9f60443877858cf8468832fef650ddd6c2c595d1fd5f13e7c067b4bd9f57579fc37b2ab1500bb8b83fd29e532dfcd4671e824a26092aacef2c9f5e0ceb47c6ac4706df21f244308a05042 }

condition:
	$a0
}

        
