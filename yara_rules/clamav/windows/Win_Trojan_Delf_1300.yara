rule Win_Trojan_Delf_1300
{
strings:
	$a0 = { 4a17d2731e69405b21a5087a21b6929e6ec936695f42d6e72d5c7f1bddf94afe1d902f739217bd36145bb06fa6c054925f5d92d0bb253b8e90e5b901b97342deb901e7b21579c875ab9a0fa6407b9c94aae4571ecd0aae5b5ccb8d79ffffff97be7a7f7f7df9f7cdf3efddcf3cfcf737efcf7f819408a0e0ec7e8c4df8705f1c6e9cff7193c174bab4641a37 }

condition:
	$a0
}

        