rule Win_Downloader_Swizzor_215
{
strings:
	$a0 = { 30ac6f2fa7fbe3f03d0865f728f976e938fd390caff6e61f8a0d82496b5ba493876027da87b932e9ec5111d9fa5dd7354f7ad3fec5ad2edcf0285e6883232676ad3bc7150c5f9441023cb7d8daba31c0b12b69402597e60a4751e77c430160e896460ad27b0ab2d790c146e9dcb8e1be73825f8fa797f279dd59dd557caa1a60ea70c7f1940ccde8af0a05543a634c2ec21113adebe1 }

condition:
	$a0
}

        