rule Win_Downloader_Small_562
{
strings:
	$a0 = { 461ef1ce9991d53e12712b50d74a85c5009d4e3d5bd210f6921de43c14b4fe779f36a910496982d091481dc9b7262c1f34a87bed1b4549787989b4c1bd2b77f5260714755a4d0ce7bd2c44132399c0a83c4c200471d710a3a23b8f846e7a682637fe8b32e35361246378a765140e44d4e756978d5579cf3af2b61a415a78781d566e3fd96265d6001039cb734e90d595adba8245f7 }

condition:
	$a0
}

        