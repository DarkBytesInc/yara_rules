rule Win_Worm_Gaobot_40
{
strings:
	$a0 = { fb7020b96b9ac3189ceeb702d9fc6b5063bed629dfd94add58dd1d416755556d41ed83e87a9cda35ede979ede13a6bb8ce1eaeb3a0a6429db9c3e3a012ea928c0e28114cba942d4db3bb3bc8941c183b79bed5167919f7d1e950af1c59472d99dd7ba5f6e0102ebdee3f6a503af7ca87dfc4 }

condition:
	$a0
}

        
