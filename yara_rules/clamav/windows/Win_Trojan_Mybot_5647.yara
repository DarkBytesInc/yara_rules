rule Win_Trojan_Mybot_5647
{
strings:
	$a0 = { 3e5eeb5de8fe887003cade62d0c592520e6c459ea5b163c00101f48ada78bc85954d6d53fd5bc9cf1d638c14b5971d378e5c3220851305c80937ee8ab68d50282df64939bb0c944fe1f103c55ebf6f3a79ebc70b9a26145a2ad9d1b30beb9ae725f8c645a76c3083f3418d4b0dfc6b9db99fb8b2f070c45015190095ae30772f0ebded9a4f6ee5c9f9bf2952 }

condition:
	$a0
}

        