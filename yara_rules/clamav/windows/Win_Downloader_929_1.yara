rule Win_Downloader_929_1
{
strings:
	$a0 = { 0ee500895baad63dd0d32d39ebcb7437e4b6f01b7c2fedb190705e7cfbed8c82b70bd523f7107d5bb6c6a1cac29cc255b5e4c08f637f9d0e8bbd287dc2b5ed34e09180186b7ae8de27b6b9e883df78356401de93ed7d297dc9bfeb15 }

condition:
	$a0
}

        
