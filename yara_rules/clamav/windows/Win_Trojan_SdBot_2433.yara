rule Win_Trojan_SdBot_2433
{
strings:
	$a0 = { 3b6ce6d0e470ca4ac779a5c1469f59b3d954f14f479fca702336270cc68897b4ca356240b67f4af892b7f415931f8afe0642324dc740fab6819f1ca253d0be266d66e77e6225acedba93a6492851c83a847be2829b536b8fd2ea1a94e0254acea385a81a941f921ecbc5c022738080a45ed1d44097d3bbb0c419cdabe0fe27e4d74e21f1c568a043965d0740 }

condition:
	$a0
}

        