rule Win_Worm_Mytob_404
{
strings:
	$a0 = { 264f2eb0f1a90da697b29a4857924de10c66c61fed1fddfd1e0649ed8541af484d696670cea0faea41a5533992d601f35e511a7355bcd0f799e587c0c1acb42319211321ac9b2ea792c392b8227126a9884fee6588fe7199754f04b2c9797c12761ea8c5d39f999aa993145beb9a7ee00db3f84cb7f08f7576fae6c942796fbd80fb1b916f9f0a69880e4b54e074586b9639c93856fd }

condition:
	$a0
}

        