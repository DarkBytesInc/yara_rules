rule Win_Trojan_Hacdef_99
{
strings:
	$a0 = { 666bbf1a7cf5da4891f7a76b9cbdc5413c4b139815a13dbce36d6b1c8230d8c74b841cafc2feab0b1dafaee08f6026471217a88f2d6d998f9997d50e63de84f8c584ea1bab7e8ecdef43dcb46a9b4acdc6d78ff8172f4827e4df3da4252e2987a20c450063c742512f3daf3b2006c54572f95f38c7cacba855fd0f9383c7bd8afffc4076145bc2fe6067f5ddbf9933dae46c031cce }

condition:
	$a0
}

        