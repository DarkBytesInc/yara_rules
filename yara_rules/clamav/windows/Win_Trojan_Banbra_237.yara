rule Win_Trojan_Banbra_237
{
strings:
	$a0 = { 532235ee01ece996655996dac8bbb9b8ca15aa59567c5fecff4781bb7a79786161861131b92f8bf50abfb715252f04bbd8d1e87dbfcfb95f9810f0b4e6d6ee36f7faeffffffffff5ddc7aaa67b86bc8d95cc8fb0e5b5b0e9cb9cd1b58eb390849b737c875f6c680aa0c4ff454f3f2c625d41ced4d6290908a0442f3d6b14f2c6 }

condition:
	$a0
}

        
