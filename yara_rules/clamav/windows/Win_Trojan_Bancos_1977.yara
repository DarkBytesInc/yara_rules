rule Win_Trojan_Bancos_1977
{
strings:
	$a0 = { 9fb865b7fc63b3c94b8bf4ce75151fc481bb28afd948d286815e052ed7c9d06c33dbe6438be299893ee06bef4afc1e55da8a7273b0db3bbbe8152b903a8fa8dfe3485e7ef0f99952d457bbd1b120a864996ebd8d7d9b929160c465838ef33eb6d3a380d6abee4357a3b5daad25db }

condition:
	$a0
}

        
