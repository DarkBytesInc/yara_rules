rule Win_Trojan_Fakealert_114
{
strings:
	$a0 = { 8207a6aa7788e0984a09ae295f2ba089892903f64516309ff9950e914e44cf598b41712a714fb25189119cd7ad1657b101f27bd99eb7fc2db670292b793ecc613f067ece3620e00976029a2669cfefa8b6345625c80d31da812184299e2a52f0fd2b5429 }

condition:
	$a0
}

        