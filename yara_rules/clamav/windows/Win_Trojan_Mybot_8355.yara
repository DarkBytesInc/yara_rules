rule Win_Trojan_Mybot_8355
{
strings:
	$a0 = { 020d03254c3fcab891114ae480d339cdb939938b157ac839515f6ad8f95f184e1c7975dd484eaa8cce6be2b37f83d60d76a7f3e9d07fdafea6e69489141c5f617ef2ca6a5efc80bda0ab591d047c112f2dbc56344c }

condition:
	$a0
}

        
