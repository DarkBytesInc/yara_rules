rule Win_Downloader_692_1
{
strings:
	$a0 = { 929ebff6b1a44587de6b09774013fd0ff39c1fb4ad0c3048c8cdfabb11c813b4558ce53ca66be63f605a0280dc28417e5ac292fc9f1d223f3af5c9d624b5f654ab85271c330ad76aa57c2f0f4a84aae806f953e3a9ed162361 }

condition:
	$a0
}

        
