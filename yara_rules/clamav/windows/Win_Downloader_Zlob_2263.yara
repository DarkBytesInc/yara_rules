rule Win_Downloader_Zlob_2263
{
strings:
	$a0 = { 8f366c160b925557cb07c5644eb7dc1c2959d22a9ea420d3b75320638518738a76d9f60cc0ecc2d568535996cd1a9e89a6c3ccb0f0fffb13cd6b8ddd4879dd94a970472eeb96f64a8d62d621cd09066cc667e28c2bfdcbcee2c4 }

condition:
	$a0
}

        
