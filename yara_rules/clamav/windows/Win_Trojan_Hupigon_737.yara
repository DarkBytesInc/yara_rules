rule Win_Trojan_Hupigon_737
{
strings:
	$a0 = { fe048d8ae50be3391fe8aa46fe8a6936d39bb7e16facc1f6d6287b1f0c5017760da17922a41d73c2f88c43f126f98d57de9a77b0f17bcadd8df5dd52b13aa568f0d73d78d6cebd8724af593f37076288ca5a36cb8af1d885 }

condition:
	$a0
}

        
