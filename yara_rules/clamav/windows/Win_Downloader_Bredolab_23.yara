rule Win_Downloader_Bredolab_23
{
strings:
	$a0 = { 83f35a8d1da04e400083ec4c81c1c54340008d1c088bec8914248d4c24046848b440008b0c248d352f11400068ea65400081f1a186400087342483ef0383f2548b1ddfa14000c38b159d1d400081c0106c400003d9890c2481f6a63c4000873c2483eb028d3de6af4000bae53840002bc181f1ad18400083f73e2bfa1bfa81e7 }

condition:
	$a0
}

        