rule Win_Downloader_Small_3257
{
strings:
	$a0 = { ff3516149e86ab3d034c590028007504eb34eb253dea00295befec02eb1a0bc0751400eed8809feb02eb0d43eb8ec9c20800f3772cdc00f03a8793deb0dbdf44d31fff4db19dfd4dd8a54066f8519083c4fcfc49ba666d50b2b9cdb16a99220b1dc7148d50974da42d6a0110a6895316c393c2eb383e10f4f468774026e9293f80bd412ebbc7ff3c1d5baf25 }

condition:
	$a0
}

        