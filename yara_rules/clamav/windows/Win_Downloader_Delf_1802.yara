rule Win_Downloader_Delf_1802
{
strings:
	$a0 = { 5cc8a08e018771c0df9e165c555920830c324d41c5830c32c8add1d50c32c820e9bda1a5c00021839560b1f58c94242d0600484c7ec16dd267060d216b1b12ab473e2993d406bd39da5048d1a519649041a15d697564904106714d591c2064209c9873009e4bf9c6b0feab86c701987132d4bd2c3c7e307dc6b78270f1 }

condition:
	$a0
}

        