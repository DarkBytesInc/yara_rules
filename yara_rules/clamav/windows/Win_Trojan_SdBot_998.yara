rule Win_Trojan_SdBot_998
{
strings:
	$a0 = { 4959a657faf6cf9f7f4fc525555c12abb6d627624445900b9c6707166593fbc2326cd4054c0f6b511505f97bd25a9364ee477bf5420afe6e635c095547de6165e70e4ac737ff59279c0c0a76c77c3afe27aba8b95607a6dab667f40b0d7dad8967cb862f5c4995a81c3b4b3eb4dda7cfece9c2b2d69a08975da6bd09b59466977a1a41f059b6c04f16e751e0e1c560cc55e055a4c753 }

condition:
	$a0
}

        