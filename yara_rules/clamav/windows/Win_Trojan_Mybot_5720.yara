rule Win_Trojan_Mybot_5720
{
strings:
	$a0 = { afd1c146a714a73683c61bb5093164487afa21834b538159eb69a45c8ef37b99aab555521d6bb244fad6b3d6fee00f4dda44edc1de328e92dd96179c4666ed238ed820e5eaac270a41c3160a51edef617573a38b29d5b32a868e }

condition:
	$a0
}

        
