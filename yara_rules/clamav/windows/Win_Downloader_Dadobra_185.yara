rule Win_Downloader_Dadobra_185
{
strings:
	$a0 = { b2bd0d5c5455fa387e67e602038c0e28a6e61be958219a20962f03390883a8a1a308bea25938a199ba70af5a810c7b65f3729acd766b6bbfb6bbbad6d65abb4bd926ea6e0e8c82646b8aaea2589a5a5dbc56a8ac8c42ceef79ce3d33a0b9dafe3f9fbf1f87e7dcf3f29ce73ce739cff39c977b2e1f65e32242b385c2a5 }

condition:
	$a0
}

        
