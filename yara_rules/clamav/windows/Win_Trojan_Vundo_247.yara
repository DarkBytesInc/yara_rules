rule Win_Trojan_Vundo_247
{
strings:
	$a0 = { 03d3516885380110686f5a0010c36681ead5a283c404e939b100008be581e1892da8025d32ec32efc2040081e141155b0d558bece96be300008b450832cec7401c000000002af78b4d08837924000f84ab8b00008b55088b42245068b0c60010689fd80010c3c6052d6001104bc6052e600110a9c6052f6001100b2bd3c70590940110e4c9ea7932ef81c187 }

condition:
	$a0
}

        