rule Win_Trojan_W_59
{
strings:
	$a0 = { 5fbd63d8deaf1aa09f5e11417a429a55bdf190fe18dd2f6177bb6a8250cf6bb2a872e32eca2f8542d0bdeae6acbcd7bb013c328b50ddfdc6b0d8fa445e3c963e72ac1629428de7d71a2ab8bff1e734a00e479e0da9e528001ce9d3664cbf34962fd1deb62bf9a5a9eb4b8b8f7fd3 }

condition:
	$a0
}

        
