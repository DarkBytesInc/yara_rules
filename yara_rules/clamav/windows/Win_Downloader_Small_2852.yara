rule Win_Downloader_Small_2852
{
strings:
	$a0 = { 8b201f106eeef38aa76b318d1b99ed06cc03e487ebd13e65254c901ee74934e049136e74059267d449ff6fed74cfb49ef54bba35bdad693da80cae048900bb42f514238e425a3b3ec5aa60756db164ff8e097f8315c9032fbfd6f94947b3eab73b2900c1776d203c1819ace75653d4bf5bcf }

condition:
	$a0
}

        