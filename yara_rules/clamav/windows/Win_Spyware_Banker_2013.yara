rule Win_Spyware_Banker_2013
{
strings:
	$a0 = { dd11f8e27704f08deb8c5e90637dae5e767dc7723fb2c4e37cfd096c3e067ef2cd9059663c0a1f184dfb01e9ef01635f5a0e7dde15eaf3fd5172bf05ae0f1c4d27da49ade752e13eb1bc11d5b401c5fe72aeae903db3f19c40c6a3aa477b51d7a203a75b13875762f960e2b352d17d0d1e2e }

condition:
	$a0
}

        
