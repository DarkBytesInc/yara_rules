rule Win_Trojan_Banbra_220
{
strings:
	$a0 = { d3bbcbb22ccba99fa7b8cfeecb72852cffe1dde12acbb22ccc00ec9a55d40118c15496e55df201ddcc9a5a3b4fb4ef001cf0015996ab8ae1b1cc50967755afed01c3d3bc838aaa6bf101b62f5562a0ffad00ec85884c2ad1b22a5711b501f4ae1a54a9a9afb5bfd4aacaf201c3ebf6f501cbb20c41eeeba8c685aab22cf6fcaf }

condition:
	$a0
}

        
