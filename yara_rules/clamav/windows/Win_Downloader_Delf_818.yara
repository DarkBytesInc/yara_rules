rule Win_Downloader_Delf_818
{
strings:
	$a0 = { fe02cfae6b4063f0c8f73ced92b7e13ab1cb3266c2d7e7028cd65ad02558e96f404db15dcd31a447e31314a2002927f02a610ac24313641d765c33d96af4461b00e8cacde8d22bde45342af5e177b8c880c680a49e8c34942894774733eed445eb1d90dc10d0f49a03b65ba98696ede54c6f8f5bc0237c902bb4c41f8b13f3c23dad606938c6f7 }

condition:
	$a0
}

        