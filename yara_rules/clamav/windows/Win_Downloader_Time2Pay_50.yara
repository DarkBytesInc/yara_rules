rule Win_Downloader_Time2Pay_50
{
strings:
	$a0 = { f0a26efe041fc164d140f074f475e068e74cfe64f440c4b16cda6d8ae1019a5618db11c86c16523243d73cf6426ce614ed21a0b980526d7ef967803a4257795ecfe6c78a79a47ebd966bc48cd6964eb76ce9c53248751b5c69e39bb190e82ecffeb359645c9d4283425240d253535f732a3a46ad468b44d690fd53 }

condition:
	$a0
}

        