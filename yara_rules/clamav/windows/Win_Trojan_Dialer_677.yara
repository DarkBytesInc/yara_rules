rule Win_Trojan_Dialer_677
{
strings:
	$a0 = { 2bffff47c95c40484b45595f43555252454e545f555345525bedca01a73a7761f55c54574f56485c496ee56e6baddeaad32778706c280b1bdada576a61d82b74281550d6800698dacf385f65bfd547383939b33331363320004afe7fb0172d3031325f352d6c6639637733c2b6fa3f61626f75743a626c61812000c21e65037f4f4b4dfb5b858db3333730309706287c02416767 }

condition:
	$a0
}

        