rule Win_Spyware_Banker_5585
{
strings:
	$a0 = { b56b761dca8cfc8673a2e41dd9c37fc65139a640f82d0d559d4bc7d8a3c5c15a1d196552d9b0bd9b7f69ac01a896a8460057bdd141cffb228f209e8a5caf84e25464fe0f3a8c95f2a3061216c0e80680af338398bfd03547cc5f9653c90eb8ff384592688158e9bcb955d621e3bb5a2e51f78e23e0a0f8a83c7082f61ff0cd75920613ebcb681665e5720f65403839e7544375fc9a7d }

condition:
	$a0
}

        