rule Win_Downloader_Swizzor_602
{
strings:
	$a0 = { 36cdd854dbce5522206f785375ca3e20de6f54431caf2ff8b7e0ba29001f8f2a141fc78b50fa92cf5283366462deb3c4bb0d44c6bfbce808fc1253a765bf6d52e19576d42230b9fcfd0d3d93dbd2834dcf72ee610df1a6d9002781c64cf81f28a46e67a77fd846d8c7 }

condition:
	$a0
}

        
