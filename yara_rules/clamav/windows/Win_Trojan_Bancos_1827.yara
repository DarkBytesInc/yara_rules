rule Win_Trojan_Bancos_1827
{
strings:
	$a0 = { cac24248c7ea59e7b344296193cee8369dac265b946832fd4b939e88d18b15d089a380e3e0f8687bc1d6bfe1751aaca735fac86d7a9e93a07937bb804e33e001f44ac3654661 }

condition:
	$a0
}

        
