rule Win_Downloader_Delf_1845
{
strings:
	$a0 = { 44c8a08e019f65d8f7b63e74697d20830c32715559830c32c86145b90c32c820cdd1d5a132c82083a5b9f10103840c9560b1f58c94242d1b0020317ec175d267060d216b1b12ab473e2993d419f4b0685048d1a5a1b19041065d69410619d475714d80908190599c98731c9e4bf9c6b0feab8660c6c970c7d4bd143c7e }

condition:
	$a0
}

        