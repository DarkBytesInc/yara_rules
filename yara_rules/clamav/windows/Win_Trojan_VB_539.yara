rule Win_Trojan_VB_539
{
strings:
	$a0 = { f6c854eaee2ff85a447a5b40fb584815d97e40eac0c63c766acbd0f39df165fe01a3751326e137b0814097a1193fc38140c5b537cdda9d55c343411029a99d8b547483d6eded5bc3ecd20c767e8729cab981e4dbb5c94bdb71782ddbb957d3d07ae25921101216f06da24fdcdce7a1af634a4a4cf90547dcdba624fac93621ef }

condition:
	$a0
}

        