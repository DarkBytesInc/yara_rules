rule Win_Trojan_Agent_33875
{
strings:
	$a0 = { 8d45d0e80650ffff8d45d0ba8dc24300e8b18ffcff8b45d0e821b9fcff84c075498d45cce8e54fffff8d45ccbaa5c24300e8908ffcff8b45cc508d45c4e8cc4fffffff75c46865c243006879c243008d45c8ba03000000e82290fcff8b55c8b8b5c2430059e8b8b5ffff }

condition:
	$a0
}

        
