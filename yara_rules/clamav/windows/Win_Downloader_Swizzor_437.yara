rule Win_Downloader_Swizzor_437
{
strings:
	$a0 = { 9841e86f9ba2b5fb107d3979eaa6429e15455f50a5781bb1786777ce0ae53e8e3c7d3674e39b3524b342e78a289e9a1ab83a3950efd196417d79fd79cae2f033273dfb4642dabce6d42f06a71cd670b24d3f9a73722df81dbce9 }

condition:
	$a0
}

        
