rule Win_Trojan_Bancos_1432
{
strings:
	$a0 = { a3bf5ad15ccb3a74dfa9f438199de3c9f6daa3921f68b95ba97eed1b1e3f7b131dcfc4095f7a6b884ff637c2964059fc74f27fa2a9dda5f79566117b4b477f1f437bf2ce3ef7f3c21e1e43f513419c655ec4a159e0257241c50b556958 }

condition:
	$a0
}

        
