rule Win_Trojan_Mybot_8372
{
strings:
	$a0 = { ca34bd7cd0d3cafb33ea6dcd2c069936151fd1f1b587ed300c626420b659c799629d3253b9cd69b498f5df0772cde4a06889ad8e210bda54bd54615f4e4bb29087a979423c8bbfb8178bcde77cf675263998ae6300 }

condition:
	$a0
}

        
