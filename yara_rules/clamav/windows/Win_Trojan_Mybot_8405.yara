rule Win_Trojan_Mybot_8405
{
strings:
	$a0 = { 3a851917dbeda8f1249ab4453fc75f2830c0ff54fd573f7addc26d4fdc9c015680ae83bdf6fb6c2aed0a5288b3d5ed847939c8ae20d3210ff56bd2e030b3241900f3d1ea31550461f8e3e4bad14896c96ba6f936ac }

condition:
	$a0
}

        
