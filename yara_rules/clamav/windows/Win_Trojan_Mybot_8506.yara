rule Win_Trojan_Mybot_8506
{
strings:
	$a0 = { 87349a459b74c1e5a4c85e61ca0d77df3461569161a4792434da4ebd8a5977bbdb9e2ead79bf693ad6c64dfceb35ea3c8a3c300486d450a46aae991f781d3d0e26190f0aa21706c13c8beaa3fbe9af247ae473a924 }

condition:
	$a0
}

        
