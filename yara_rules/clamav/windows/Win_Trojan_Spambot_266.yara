rule Win_Trojan_Spambot_266
{
strings:
	$a0 = { 03ba99889f1678d1fe8c5b6e095f241bb2834fffffffff5d08787b84d0eba774e2b48d4d341ab74ad76c8d5deb7e0aef1f0efc681698ffffffff99d79ef12be3ed659e1e9df9c9cbf038bc3815ee7cec850dff07a247a7943d5ffffff8ff36e621aab468906203ffbeb6f78ffcd3 }

condition:
	$a0
}

        
