rule Win_Trojan_Briss_5
{
strings:
	$a0 = { 64642e436f64655d0d0a6272696467652e646c6c3d6272696467652e646c6c0d0a6a616f2e646c6c3d6a616f2e646c6c0d0a0d0a5b6272696467652e646c6c5d0d0a66696c652d }

condition:
	$a0
}

        