rule Win_Trojan_Spambot_211
{
strings:
	$a0 = { d3caf8a4c11af7fe3ffd3f9598a68528ebeda52b2f90a5e09f46f151f3f0b0ff3ffdaf874224063d1196e6e2c7a65fa99af3c4bfb685774dffffffff8ee5067ebff4a47bbd5bc06a626d47dbe063be648d49c608afa6f5fcf47330e0ffffffff52ce8b3ba3ab4aae11ac092d69b6 }

condition:
	$a0
}

        
