rule Win_Trojan_Joiner_17
{
strings:
	$a0 = { eb156b505b55fa907b0901b324104a63c5f5badeced0d2714baf3a48b3db90424b075a6f7209495884a44d30c42bb449aead566af4d2d5f44cdcea2c3abbce8efb83191d0ad5edaced80a3def008e587dbc24e5fd671b1ccb8c1f8c0221514f6ec77696767a7ff767fed8f3dc977bee7f91ee77ee79cc703e18e80c86d }

condition:
	$a0
}

        
