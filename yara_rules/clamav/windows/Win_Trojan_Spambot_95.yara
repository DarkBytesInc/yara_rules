rule Win_Trojan_Spambot_95
{
strings:
	$a0 = { baaaf195f32a2e9dce6ebb3e844dffffffff469f3c8ff54273dd0b6c9fd9ed3fc1cfe42ec2992d3365f89d8e67bd95b10471ffffffff96cfb56b20963cf73c6660e9bd331832e87ff6404f8a077f70e5164356de3cc7ffffffff4ad5dc065d090c50f32f5dbf3108e4b7e9e54c72 }

condition:
	$a0
}

        
