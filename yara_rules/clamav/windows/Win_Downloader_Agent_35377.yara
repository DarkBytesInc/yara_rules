rule Win_Downloader_Agent_35377
{
strings:
	$a0 = { 27ff906324ff956624ff996724ff9d6b24ffa16e24ffa77024ffab7224ffb17726ffb57a26ffba7b26ffbd7c26ffbf7f26ffc28127ffc48126ffc78528ffd39945ffe2a143ffe6aa3fff9ffff6ff53ffffff50ffffff6affffff78ffffff41f1ffff28d3ffff28d9ffff26d2ffff7cb8cc }

condition:
	$a0
}

        
