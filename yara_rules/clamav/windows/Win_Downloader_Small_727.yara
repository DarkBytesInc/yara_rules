rule Win_Downloader_Small_727
{
strings:
	$a0 = { 783333342f72756e7376633332283fffedffb18052da6d219c3952884baf81b92a7143e4a7b0319bed6f97fcff6e2f80985a77002e636770617905ffffeeff6f2e756b }

condition:
	$a0
}

        
