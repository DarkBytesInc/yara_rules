rule Win_Downloader_633_1
{
strings:
	$a0 = { 8dabae95cde023813442f211bc4d88bd67561f97a76f7710c0d0003694edb81eecd3d9073d270bb5bd50cbac553cb12cbd035d9bafe427924394e53d5bbcb2383580fde78e92208ebdbb006852d729761caebd0cdfb05075cde4782350a5b5 }

condition:
	$a0
}

        
