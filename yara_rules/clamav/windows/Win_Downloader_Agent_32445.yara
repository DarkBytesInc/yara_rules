rule Win_Downloader_Agent_32445
{
strings:
	$a0 = { 1615cc1fc117115b6e727f307b6f2701e957849eebc65ed5b2b09d6c3061b6184279e0fcbce23938c25b415882004e460048f6ca0f1471b073f2ab88b0f28305008ccd4680e18fe556d00ec2291fce60d636a87618afb81f084ceb0be00e1be96103815c261ed6b62517dbba5027b2041e2428c6ae28740fb29b0b6a43b22cc1edcaa202d00826848f23046b094808ea93b03008 }

condition:
	$a0
}

        