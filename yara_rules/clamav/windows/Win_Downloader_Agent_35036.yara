rule Win_Downloader_Agent_35036
{
strings:
	$a0 = { b64db805a5afb3129a9583c271f8368ada4ddbc1cfaa83403dd8163a4daf6076ba96c789484dd4c3a87fce8f24719edee7a2c48587f1d7c4a86599deea2e1376ba578384436ce2bfb5b76b9d414d7529896ca2ff5cb8712d0b79a2ff58bc }

condition:
	$a0
}

        
