rule Win_Downloader_Swizzor_462
{
strings:
	$a0 = { 2bba34a61b70cf4fdc479c7fb83fe496a146caca0642ee1fac3538ab9bb51e45764cc64c3f71b742592ad80a278138311eb3695f141a1e00287703cb4e8ef5104a811535c3ececcb12bb5d47214ae2900e2caf86b5de4cd7a19e }

condition:
	$a0
}

        
