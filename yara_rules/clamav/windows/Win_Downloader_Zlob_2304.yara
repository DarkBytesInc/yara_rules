rule Win_Downloader_Zlob_2304
{
strings:
	$a0 = { 5dc57f5b98bc017b60bbd37ac5e089ee44f69d6b413a1eda23b032dd8923809077311c248b2c4889caf6bbafa1e3ca641a8693aeec5daf713bf972e8663b1173338e1da19bb109832744a6cb4d58133ad8aea169a89a2574c69f }

condition:
	$a0
}

        
