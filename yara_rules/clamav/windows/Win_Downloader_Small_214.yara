rule Win_Downloader_Small_214
{
strings:
	$a0 = { 7970746f79616b75641272754a6d79633172cade2cf669736b613423360f7f606fed63075375677364626c613836e0fdeddb32335f6b3738332667393735373129fff6ff9bdb6c69656e74204b69636b65642c201d783d5b25645d0ab40ffb7f775468726561647320 }

condition:
	$a0
}

        