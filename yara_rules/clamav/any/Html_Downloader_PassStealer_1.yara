rule Html_Downloader_PassStealer_1
{
strings:
	$a0 = { 2e7368656c6c6578656375746522636d642e657865 }
	$a1 = { 2e76627326406563686f }
	$a2 = { 2e6f70656e222267657422222c2222687474703a2f2f }
	$a3 = { 2e72752f }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
