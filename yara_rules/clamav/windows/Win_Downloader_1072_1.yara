rule Win_Downloader_1072_1
{
strings:
	$a0 = { d7211439157cc9a70b82e3d9e9c232eeb9c63edf84c7359fcd85b74e28cf48f7ceae000e1ab7dcc940c4c6dc3f8a8a0b8a05dc33ff1d8fca3f80f5188065ebff48c06192c91a579e6bcdd72745160eecb582c61ad7b6c8209316cdb8 }

condition:
	$a0
}

        
