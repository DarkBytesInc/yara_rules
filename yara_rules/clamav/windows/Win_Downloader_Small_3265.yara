rule Win_Downloader_Small_3265
{
strings:
	$a0 = { 360c669973527f26663f3c6da6125be58a76ed9aed91de67666666cdeda7cdeda4cdde64666666cd0c6632300c76300c663599735e7f26663fe5a2766da6126aa122427a6766666607a46266359973e67e266655a6ef22427a07a4626606ebe33b6f6666369973367e26666da61233ebebe66f666637368e189b99996da61222e5a664ed96ed224242368e7d9899996da61257edbe0c }

condition:
	$a0
}

        