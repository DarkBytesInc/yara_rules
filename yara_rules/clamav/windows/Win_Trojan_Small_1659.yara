rule Win_Trojan_Small_1659
{
strings:
	$a0 = { 7b580f6c14d7997ffb077b80819924ebd4cd39890b4b8fc4a435acd3b3593b59a79e155130379b4d66bca25eb73ad8db8eb86b043b0e558dbb68bdd18e5fa64a1b2b4aa5b64ad4466a4ba56bab1e26bdc6ac59df1a2a8eb8354ddd82722675e9a0750804624ca04cbfefcd2c988a3b4bfb66de7bdff7fbbef7fd7d6385 }

condition:
	$a0
}

        
