rule Win_Trojan_Bancos_1127
{
strings:
	$a0 = { 0f218f68e8a2d594801f03beaa80616d637f2d84fd40ea2ee619a4bc2388e3b424821fef81ec9c409001d9bd12fc6b879abf82528f03e3cc665cdcf0971eaa9a2c63b6f6108632f9b6c30e0add059ef9a587a1da80ea3b6585cf0a22ea9dfcec0ada }

condition:
	$a0
}

        
