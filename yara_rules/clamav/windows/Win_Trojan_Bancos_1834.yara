rule Win_Trojan_Bancos_1834
{
strings:
	$a0 = { 02dc1a4855391a85af2f3d61287f5b525bd0644ea1241d9391933092a8717f7e4f99edbb76dfbd77ff785d16a0a9d9ba1a0951159d694280a39748e23da7a170f2bed93fee3f }

condition:
	$a0
}

        
