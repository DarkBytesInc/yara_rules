rule Win_Spyware_Banker_5839
{
strings:
	$a0 = { c88cf04e046c5956eec6302e0baa4bba5d46f8eccd7cf7b2c4930f91a0f683117b9cfaad5f9768e2bae6cd7143bec5aea4f8a22a9aa7cbca56da1956d0fa49aba96e114557942da4956d15423bafd8f96740e6ccd29e76965d5594d6fde6b6e3316b54faf6eba81f4f7472d68edb9ad4d56e614c15f1c9ffae103a8c99b5acba }

condition:
	$a0
}

        
