rule Win_Downloader_Banload_188
{
strings:
	$a0 = { 9063526d9c8f38671fcbed835a07f1606d88d697fec568188004995b9935d1a7e7281aa38291c7d3082518c15722f11a31fde8ed36f7ab36a3487b4ba95d1b2d5151d6ea511a8e344a7df9a5454737af7066673d0d5fe063c501b8ecb0fe50d847a7a4b4fca0ab96183392d58be2090d1e767de79c4a51348e4c31498337dfe97e5d59b8ccfbbcc9ff9d687525ff161bdb9c857cb7d1 }

condition:
	$a0
}

        