rule Win_Downloader_Swizzor_416
{
strings:
	$a0 = { a1036eef481507e5707a8315f529ff5c0efb2ab1ccc234a5c24faf04728f04d231837c661fb39dadf96ff6ed68dd4d77d021b275bb67f87b90a7ba3e5513de59f65b81ed44adf00c075fb452b422d5217997707d87d52d6a554b }

condition:
	$a0
}

        
