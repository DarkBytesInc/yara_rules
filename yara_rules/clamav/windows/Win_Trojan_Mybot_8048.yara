rule Win_Trojan_Mybot_8048
{
strings:
	$a0 = { 08a2ae467e6b30cdb5f8b092cdc9b4d3c4c708edfb13d603eb1280b93abc6b57471f976e4c781177a85b83345a147e3ebd52af65dcb73a48fca5ab508c89094486bf81933090a05470be49b5fb10c15cf8a35ff3a2d413d59d1c0ba36c3d3552f4b749fbfb66d4b5634797112aca29d25480c9a5c84947d6edf73030715013bb59d700a9eacfa95fd878 }

condition:
	$a0
}

        