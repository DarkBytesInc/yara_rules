rule Win_Trojan_Knight_1
{
strings:
	$a0 = { 210cbe06b72842ed5bff9f8ab71aa83eaa8e0e0ceb4bfa69f1460a04cdc68bc3f541a4ae7412ab1972292f493bbe4a2a692e9052cd5f0b24225b3f413ded51e2f7b00343e3fe637142c708c3a38f5ee9b9ea2dd02b6ae59286e835a014f79c6520485ef8dfce592c22a9eff9e0a34b }

condition:
	$a0
}

        
