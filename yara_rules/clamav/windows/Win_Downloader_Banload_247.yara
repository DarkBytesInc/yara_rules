rule Win_Downloader_Banload_247
{
strings:
	$a0 = { c5ad4f94060294db3e90db3aa8ea459df5e2c6006bc552c8addaeb6b34e30b66bb3fdd1c9a8e13178b0ec7c4f10ddc225441467358c2687e32166a403e42ba4cafbb1bde49e6f7dc9743477953fadd8a544048a00cbf499dd675 }

condition:
	$a0
}

        
