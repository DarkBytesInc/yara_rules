rule Win_Trojan_Hupigon_884
{
strings:
	$a0 = { e6fdf674f662cf3ea1a85cce61f64f66f7ff269d81c372f53d96ca90059c87b6555e9e29bdf8cadae08cafcc82d0c5bf7c72ec49a38bde4c303583e12cb49a9c6132a3a7cb8e41e3132f2347f72e0b72aaabb5f66fe4ead398a9917f61237e }

condition:
	$a0
}

        
