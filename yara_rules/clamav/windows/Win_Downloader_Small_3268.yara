rule Win_Downloader_Small_3268
{
strings:
	$a0 = { d8101413501014137501726c6d6f6e2e64dbbf03687488703a2fe277df02c16a6d766f69f7b86e6574fe417c64f5e3b14e61dbe34cf3738e12ec2ef258f7c043 }

condition:
	$a0
}

        
