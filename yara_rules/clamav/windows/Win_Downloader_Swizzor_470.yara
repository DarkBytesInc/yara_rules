rule Win_Downloader_Swizzor_470
{
strings:
	$a0 = { d93ce54141cfdf23c4c543126914f773c8da24d068be7f33f1d2e19ac29ec8e6ae4f91bd1fb9742cbd03d6d16aef2d87917ff1fd44129be2367a6e35bb2e8e9a707461a9577a6feaf99d65a241d0614633ff35e12fd1d49e419c }

condition:
	$a0
}

        
