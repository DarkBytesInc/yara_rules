rule Win_Downloader_Istbar_88
{
strings:
	$a0 = { b56a51eca1548541dc0daccd24322540fdab65ba0d0fc19def146b94d25414b7204af935f9a81bf2781f1cbe2834006755c5b721be304f3636f64636d896c20fc550a5636b821d47b94a331e892e9361ea0b1c1ba3d82d8e1b777288b563dd2f267ae1ee1a5077e2482b49f863bf30a06c878e1f84bea6553c59ee0f54daaf079ddf8675feff65ab7bb176b7f06d4406a528c05d0a68 }

condition:
	$a0
}

        