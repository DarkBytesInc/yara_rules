rule Win_Downloader_Agent_32386
{
strings:
	$a0 = { 5fb2fb40c44950311a82edee20c7eec8d3f19c9c6c11513444205239f6a279d383b3c9b21a1b045360012be4b2c0c921f13d3d719cd59a1d8de29ddcbcc9509a67e357c75ec90a3fc90de450f161d2f1d953b27b9c2263b6b7e87c909798af01e880cd9c467d10c6df28f1c58be844728dc3a28030cc3e0af86e91cc3876018b8cb132803edc93597b7bc9849d11b670ff54ebc5 }

condition:
	$a0
}

        