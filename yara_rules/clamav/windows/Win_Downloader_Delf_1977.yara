rule Win_Downloader_Delf_1977
{
strings:
	$a0 = { 58044279808e5bcf6c04576f7264a0f36c5a03ff80084361afc53ae1696e05e0b5109c90980a065374dc65c15a7267ec3ffa4e0f04e7b058165c33686cc7e3789e7064c430e01c31b39c170007544f626a656374f807bc1cb814160e794379736d1811006123900f0a49726661636500683855cdc0f37631b24603c9024079cc83442404f8e914004547a109 }

condition:
	$a0
}

        