rule Win_Downloader_Small_3071
{
strings:
	$a0 = { 61fedf98d4d97e1713889ea58d3d496b705e15325471a8129ffe161772383f96803a299882c45324284417109b5ea4359a06721cb88c1e20260fa4e97bcb1b10570f5a240e68647142a92f180b1689524408750670b924126cca2b578b0aa9076aca80501b62789e20e92130a23e7c0141de41bd82b02e3218d489a06c0cd1eac60d3d1174dedc955afc05267388152e531b976c6cc8 }

condition:
	$a0
}

        