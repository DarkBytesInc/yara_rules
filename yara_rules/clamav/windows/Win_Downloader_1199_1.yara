rule Win_Downloader_1199_1
{
strings:
	$a0 = { d17a736e9c279696302f607e8fbc6ae12c2bf91774812edc8a4ec1804e89cb273823db22ecd9351d2ffef212b5fd3cc7a128f5a497f328faa08b471c42c80ee9b9e3b6a5b6a9bd3df0487ad3803be8edc0c6e9f40f50ce1f2a7b9bbe9485267db6f63865 }

condition:
	$a0
}

        
