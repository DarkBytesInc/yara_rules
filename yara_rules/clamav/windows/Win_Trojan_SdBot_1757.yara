rule Win_Trojan_SdBot_1757
{
strings:
	$a0 = { cdf423dc7ac7f13ed127eb5501bf9841c59db3baf9d1f14afd3a44b3cdcc901d4facb8f37751b501bd9c62381a01f39e05156f421353328ccb799766891d23db4f2643eb69644e91c95057d4dee5891a1920e4d06a1b74e36b10c51f1acf2838f6562abac5fb0d07 }

condition:
	$a0
}

        