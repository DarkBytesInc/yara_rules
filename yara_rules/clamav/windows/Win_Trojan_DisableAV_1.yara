rule Win_Trojan_DisableAV_1
{
strings:
	$a0 = { 7768696c6528626c6f636b2e6c656e6774682b64727765623c3078343030303029[0-48]3d626c6f636b2b }

condition:
	$a0
}

        
