rule Win_Trojan_SdBot_4033
{
strings:
	$a0 = { cf17a20de67e787742d8cba93e9525cc75d4d0c383c0de2e0db31bb5d65491b76082dd4a232f6e41ef75ab25cb7ee5c09aae2b1a71f13c95d855f8f09ed079814589699bd7107445a592fb363ffd15c03207b8db3c7d }

condition:
	$a0
}

        
