rule Win_Trojan_Bifrose_394
{
strings:
	$a0 = { 28fdef3845229a47b13225cc53faf31f1e58ed324926443c42dbf7a762032ec17d6eb851bb3e52afcc62bc6155787e35cdf80ed8a515563786720d524922261c5f7e35d864567f4805bf0b92c52b2a4c35390a53f18342f4250e50bc7a260a18870c11cc003afe235a669615e90adf89faf1204051fb217455543e405d038048c8344a35820ebd497b034ff1 }

condition:
	$a0
}

        