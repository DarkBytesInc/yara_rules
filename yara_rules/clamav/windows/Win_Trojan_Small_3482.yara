rule Win_Trojan_Small_3482
{
strings:
	$a0 = { 1e1a74cf7e364fb278a2cb5ff6e1e03ce22127103c64db02e65c6a9b08e8f1c643dea21264f93622a6916dcef720605c5bf6946bfad1a6f17df6f9429ca07f495f23e9682097cbc28ea78b623ba1 }

condition:
	$a0
}

        
