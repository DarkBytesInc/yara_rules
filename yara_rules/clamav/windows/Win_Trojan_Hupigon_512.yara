rule Win_Trojan_Hupigon_512
{
strings:
	$a0 = { 09a422c520adfaa4c6df8b45d314092063384fd23675ced73b5361f8311a407e338e38a35fc92fd8a6782500a9c3e944ecd628bde828f2f6dc092b018d1ba9546e47ff9dbea06bba48ce99577b62576e0a301e480eedf62aecc4e5a5ddad0ccb5a931733 }

condition:
	$a0
}

        
