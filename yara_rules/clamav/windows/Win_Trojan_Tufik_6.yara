rule Win_Trojan_Tufik_6
{
strings:
	$a0 = { e8000000005b81eb001d40008beb9090ff3424e872f9ffff0bc07505e9bf0300008983b61740008d833f1b400050ffb3b6174000e8cdf9ffff0bc07505e99e0300008983ce1740008d83321b400050ffb3b6174000ff93ce1740008983d21740008d832e }

condition:
	$a0
}

        