rule Win_Trojan_SdBot_4194
{
strings:
	$a0 = { 9d5a4e1d2d87e7eaf00effe5d18b69860a0290edbca4dbd8410d1bb83dbe33adecf5cc7a570cf185d33b9fea4e8aa4e85d82220d35ecce11c81a9eab82ad661d7862eb235cbd6f56ec86c2b9bc791e7e53c42d93ee87168cb291d787a1f3633004a6ddc9fe8cff5decee1ad2bfc9bebd4a1f04506188f0f428c3633a49a12329 }

condition:
	$a0
}

        
