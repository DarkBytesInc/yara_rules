rule Win_Trojan_SdBot_3186
{
strings:
	$a0 = { f423e485bd072540846bd4aa5d270f63bcf730531ec6fcbea34e01fd0f544033658f2c8440c99cfc6763bdd33def9384f52fe29d9e4a62c91f4fa32ee2f1484711f96755055885fd5fa03edd68962d9160bfbb94cb07cf35d4c0d847432b592073b606a5839cdd317d2013d97993f612fc625825ffafeeb6af3976623cc6c423ce3e648804780283747d98e39dcfd53fd94d640205ca }

condition:
	$a0
}

        