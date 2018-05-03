rule Win_Proxy_Lager_80
{
strings:
	$a0 = { a388a5d59aa28b3fb972d4f489d9051fc9f12ffe678d2d1a4b28af5b72640dd301bf2f7d7d65c733635243dc16259b5f420ffd9819cdf0eef232b7d5c6659b2fafa7fc5dded4ad6d66caad41fa693257662a3f1620c4bfe56b974c85ddec5cba634f8e375266bfa9c92d1a1baabca6e8999ea6cb83340d9f8528dfd4be4826df }

condition:
	$a0
}

        
