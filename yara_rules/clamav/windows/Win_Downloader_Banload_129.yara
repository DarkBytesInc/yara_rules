rule Win_Downloader_Banload_129
{
strings:
	$a0 = { 878127100192c1807c793f13161c1919777501c00a036c2e060a1601673613153ad380115683775552163c322072c4e0c3b3d830004e384245082e4b5b5a59493e300460acb6ca4dbaf077ce8a25be2e6b51821f03407712427b617612f446520668870a429a9492b05c586bfc8a3d69026077e2c0b22ffde3993d28cd }

condition:
	$a0
}

        