rule Win_Trojan_Rbot_37
{
strings:
	$a0 = { 48cfb5b9f0155dfed96b38c4aca472a2aca055b7e61f6f7631456667705de30f8efb75c4e39f42896aa27ce5ab5dab9a4a8a0dea8f7bc0e5a3b4ca819ba701bf9ce3eab79b6dad98aad5c59d9a37fbffd41ef0a0ad8eb1f30ac48e1d8797a518bf3c59bcf9631b7c053481132afbc25ec307de607e1bdf20 }

condition:
	$a0
}

        
