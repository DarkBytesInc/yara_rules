rule Win_Trojan_Mybot_4711
{
strings:
	$a0 = { 6f604e737f7c9e54989d45ea7d086a6225cd4db4d1cce7527c37eebd641267c2674c01baa159bb54a6daf5270929349ad26542a177b5ed13bfb0edd3fbf7398c8b2840178cff926a8dbe632a910eca8ed78ee189d30aea265020ecef1ed60d788058e783e63072f289c84d47dd773b65d7eec74ee78e6e89e473c48327d63c874fd7b22d6a678a65d5a84e43471ee1a82d7d908768b4 }

condition:
	$a0
}

        