rule Win_Downloader_Banload_387
{
strings:
	$a0 = { cf7c7e6fca7cce012629f75c5cea1cb3d939626a53a52e753e164e6a581ff30e703f1c67e8ebc80cd78b8dce0a4b2c713e189690dec567455c5b2808608b7255ac016058abc0cee575303c3c1ade5288d364c27447aa8c5fc17d84b5a31f603acde0a61a }

condition:
	$a0
}

        
