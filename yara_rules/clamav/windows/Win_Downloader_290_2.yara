rule Win_Downloader_290_2
{
strings:
	$a0 = { 5a50f93ee7d5b28a77f6700c85ef68dda9402108971ad8d5ccf8bbb5117915b41c78c8a4339019032ca2787ebca8aa9c495ca584b4fa140a017d00ea08ae53004209dc0ce01cf313a93ec05f5897 }

condition:
	$a0
}

        
