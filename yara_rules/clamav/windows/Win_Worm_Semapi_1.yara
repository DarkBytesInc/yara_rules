rule Win_Worm_Semapi_1
{
strings:
	$a0 = { 5d00976020fa5eedb9d0274004e90097c0274a04e9c09800275204ea809d602a95a39e1bd1b7f76193170f4cb428982d86921bfc618ef5b42d8d9a978820d0c096724665c8c17d8bb2eb6ed9b5b8bacec6071e3b7d0110a3e0fd599617d6d6e7 }

condition:
	$a0
}

        