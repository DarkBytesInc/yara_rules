rule Win_Downloader_881_1
{
strings:
	$a0 = { 3c5161ff224aaef389b1f90e5ce18d04dc3ddcfd5a2bbd0c40fd5ad6041beef106647f7e7c59ec8d48677ae9a0934459f021a913c5553fb91c748af4122ebafdba0ebd68f37c75947d0c8948853f77f36a8d18e603f0c463623a8343 }

condition:
	$a0
}

        
