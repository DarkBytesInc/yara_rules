rule Win_Downloader_Small_2980
{
strings:
	$a0 = { fd4ccf036bc452bd6f2c0dfd53528d7b440be63153ec05e1914c0ca61ad083af53a0254d174cf097f7d63fdedd262560161d8e3fdbd425d79cca928a994c8bc1b098dc056dda0511f77b4e34ed47d4a7a4a4c9d761923ff7ec3dad20c6a1136b8ca6d841dea32d7e50cd78f083e7c46a7356 }

condition:
	$a0
}

        
