rule Win_Downloader_VBS_154
{
strings:
	$a0 = { 646f7768696c656c656e2873293e31[0-28]222b7563617365286c65667428732c322929 }

condition:
	$a0
}

        
