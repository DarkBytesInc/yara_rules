rule Win_Trojan_Bancos_1935
{
strings:
	$a0 = { de296aa4fa6a167ccdbb11b0bb5bc6e7559c18c71b03ecb027b80d94d6c28df56699737dae1966db19c598a888c4949e5ffa2e6c96fcc978903533574d7a1d25046846e31382d071b11ea6449cf94f35ae5ba8c9bb1f2d63fea1 }

condition:
	$a0
}

        
