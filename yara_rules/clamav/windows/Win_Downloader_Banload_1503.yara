rule Win_Downloader_Banload_1503
{
strings:
	$a0 = { 85f20790756dfe749d17e270fd6219576c9029bb42349c1159ce5656ec48339181b936a9490539af7ebbdbcda56fe5edbb44ef3704694e293c04cc8fccf04ac96fa00e73b789d4269d2cad94be81b8529ab657b5ae2e03ce7a27d380ff5722bda26859d7eb44eebfb8731527e104e2602a97d4f5bc81c26833500eba4dbc463420259897b622b903c6aa8e0357 }

condition:
	$a0
}

        