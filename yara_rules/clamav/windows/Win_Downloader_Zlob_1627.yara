rule Win_Downloader_Zlob_1627
{
strings:
	$a0 = { a4ae27818edbfa3063a34415e994f82723f9ba2a962d23a9824569c8f84f2562ac3bb6d46bdedeeecad6f516a36392ddc7e79b3e63c1c799f5b09af408b39a0b46f0431b2b49b7ef2164fd0826f453265cc53c3a7438aaedbbf83ca820760c1ea9f756ee6894fb7d77d1e4b7700cc4418bc725f3ee67246cbb96c271cf244da9a55d5a12b771f42683ef8ef5df3eaa391be6468bef6b }

condition:
	$a0
}

        