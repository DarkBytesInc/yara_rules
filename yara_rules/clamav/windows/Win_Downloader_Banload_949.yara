rule Win_Downloader_Banload_949
{
strings:
	$a0 = { 315043da3b83e106275dc412b2945361ac23e7166be6930b68e3e1ab02ca9e4133a609520c8628ee180a66cd2211253ca7f13b8604b65dd05eb77842c744426b04697608d75b7a430be30f6fcfa4a126ccc40008d1f3c4e64f89f8e74b62e1a20dbab3111e1df43e0d2d5eb35f1c0fbc531ac0fefe5d7a092addf22478943767c1c3831c }

condition:
	$a0
}

        