rule Win_Downloader_Dadobra_130
{
strings:
	$a0 = { b6d0ffed13979ab2f5af549cffab5a9ff06def97e834f6b6171713bfc7ff5d29a5b38cda3f79e68568e8a55463c51de97ea62d1ebe908075ee8a7b69d56eebfe1789dfba288af77d85888c36359fdee78120a8c782b65ebbc19e }

condition:
	$a0
}

        
