rule Win_Trojan_SdBot_1891
{
strings:
	$a0 = { 267f27ef141cccf7c6abc65d1baa932368a82fe9a60c88c7cd472189e72fcc86677688026cbb990e89c301d302b3bdd1c2bfcaac700875db4c9995dcf6cf60c8ba5fb3e9a964e44dddf828a09214640c4597aabc9217e1a3c00ad5e7a360e5fe6a9574931f2ee890bb0283bdfb2a }

condition:
	$a0
}

        
