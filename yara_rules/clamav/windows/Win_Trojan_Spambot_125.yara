rule Win_Trojan_Spambot_125
{
strings:
	$a0 = { 130bc239f9f36120e0ffffff6ae3f87eb733ee468dc88c4dc64efcbff55fd424153dc8dad3c19ef5ffffffdbe3ab186b3a760120a6ce4c530ab20922b0cc8d01e4fb1765e99affffff7fcdaf1374c3d9a1b3cba1f0169e9ee68bd2e67247d1289c0cd4763246bb51ffff7ff8bc0b }

condition:
	$a0
}

        
