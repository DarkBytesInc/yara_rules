rule Win_Downloader_12155_1
{
strings:
	$a0 = { 19af6257c19c89bf2fe457ff6723b418812420619a572b376f9a9f56fdea5b478b19b440b7e03e402a98771e772feeadd697c3c60b3b69451fb75c978de28348 }

condition:
	$a0
}

        
