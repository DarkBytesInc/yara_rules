rule Win_Downloader_Swizzor_584
{
strings:
	$a0 = { af7d2940ba73dc0064b38aa71c4fc986d36d365b149a4448b7764f7806cd88c99791a4eaa72fb0ca7a8ad00688ea7e9ce144d0b1ba3d79c6089a8757e7923f316419c9adf91cde7073ae47a87165c9746a22b8e31c9a3e4b0d3d66d6d42bafc4ee0afebc8fc54b56c2 }

condition:
	$a0
}

        
