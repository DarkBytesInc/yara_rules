rule Win_Downloader_Small_2883
{
strings:
	$a0 = { 03c5e0cdbc8ac747cbdae1f8d06990b5f8f140da8fb1222b16c65bd08c69670c9b75484f3d4119e6cdb39f58c160ecdb73f4e1dfeccf6a07c1fd41cdecc558b30f9491a3ecdb46a1ecd134dafe51819722aa568f0ebd3c2543ae5d06165e8a5a838aaf033e6210d077ba4c45ddb7fb254939 }

condition:
	$a0
}

        
