rule Win_Downloader_Small_3426
{
strings:
	$a0 = { eaba1997b5d9ab854ce515a10e810639b3980894cca0ee2767caa1ad0c5580388a9af0f9f676108268f4f70e781f0bf8fd7bd0dc2190cb94cc0f41114bcd2d372191eeb9325bec5ea8995ce2099b6128b4f02786cdf7ae2ee8c3c9e41eb118126aba9a4ef34471aeb74f8fbc1fff7a }

condition:
	$a0
}

        
