rule Win_Downloader_VB_286
{
strings:
	$a0 = { 12a8f1580e3356ecbc1cc3a279c6201de6713c0e4414382c1d405c381ea773601d2c1c8fe3711488a033b4a41dc7e17038341a481ac81dd81dfcf1381c8e141e0814621014241e713c8fc3341e6884041aa468599ee768c4d0101c0ec7e3f0341f441f6e10c3e170385c19e41bf81a9c1bb819381c0e87401bac1a601f801fc43c }

condition:
	$a0
}

        