rule Win_Downloader_50_3
{
strings:
	$a0 = { 1724aa7fd21468f5cdb18ee0ec8a56c52ebf4647a5dd5a888458da8b06b6f289240b00c47dc5d0c1bf11c37d7be9ebf28b070ff9beb9c6a7f92019b95d5e0b8d2151b60e1f3991fcd4fb4c0e2b7ada0667a1a79b2ffea9674a95 }

condition:
	$a0
}

        
