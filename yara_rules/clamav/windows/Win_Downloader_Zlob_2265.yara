rule Win_Downloader_Zlob_2265
{
strings:
	$a0 = { 8ccaff54e4549d914c452c3de942cf6235aea3cc0bf5a53cc2634e23ff394d382f3d9a5f78e147c1abe02adefc3671dbd08c4349dc7aafed46ffbc4de22a1c8639d1fbe7114f323b901c8dab92686ffc16d62c3c27d8be9e8e33 }

condition:
	$a0
}

        
