rule Win_Spyware_Banker_4548
{
strings:
	$a0 = { 0a5d541abdc4d757b27e1036dc8eac93f8a6bf51367ba6eb4b53efe7e04f3e948adcccee2392861f3eda21074a61c66c421d48b3c0247e5eda5dec7b2968e1edaabd42472706578e05f9b0e8e12d2af5e5614404d6355ff203fe153c6df583ca31cd5794 }

condition:
	$a0
}

        
