rule Win_Trojan_Mybot_4741
{
strings:
	$a0 = { 2a9eb015b16c3e4437a51a558faa5bb90cc8cca7f9c7a30e746d46b7ad43685036e10e878b256cb4cc1e3c1f92664e572a10ee5222d5fbf3292fd79f079b6fb919f1027871e2fc308cbc55778af75d4ed386e417498b937f78eddee627b6ba1e1e5fab484d38df8f4af76cd9526b81c1c9f95f7ca568757bbdd584acb5498aee8e61d6a5e9c63bc08566e478b3e0882cda3af49f53d4 }

condition:
	$a0
}

        