rule Win_Downloader_Swizzor_505
{
strings:
	$a0 = { 294958a3dabcbbf07185891a245a35e6460576531a6447e2ea55f7f40b623c2a3f7d4f694cbd891d9432ac3a77b12c35d80b8f8c6bde6fca2278cebf6e8cf0b8c920cb8b28be309281dcf5b8dc2c5581d0fd99cb41f1d0cb18bae2061b41e8b407522742 }

condition:
	$a0
}

        
