rule Win_Worm_Gaobot_46
{
strings:
	$a0 = { 67753290eeababe42921fda4375315804ef99d90c97f459f721e5cb7ffc5e2dc917102f87d87da1fd08a43beea3f854fdd034654684f453797cd88f5fd1d98a68dd875bf6bdfc081adfc2a79b2a6bbefc8ea3c51ebc4ad3951166f75f3c44a66c42c2a28847e413cdfd270bc96695fef3cbca806aeec8d }

condition:
	$a0
}

        
