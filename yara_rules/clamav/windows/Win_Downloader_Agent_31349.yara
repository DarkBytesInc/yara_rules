rule Win_Downloader_Agent_31349
{
strings:
	$a0 = { ec97300ff0baa5a337d944402ce04197e09bb45dbee40a98e4500bdcbe0e02d6099b0a589328f03dcc06d937d8d810f23027981e1b2874d03f0e2df40584a6c06b1c25254871a1602fdf2076072afe756664db680d215850d44d986467d15bd73d55d54de8b8642bb66e92817414ae882b2cd0ee615d480ff42c2ad875c3c8167360596074057a29f979492ed43fd0ba0cff6f3e1c21 }

condition:
	$a0
}

        