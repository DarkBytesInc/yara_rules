rule Win_Downloader_Murlo_5
{
strings:
	$a0 = { 5589e581ecfc01000087fe56575355e86f01000089c781ef080000c0897de8217dfcf831c089c181c99806440083f1ff4129cf037de8897df489efbaa8010000f7da01d7897df031d281ea9d4b4100f7dac745d8000000003155d88b7df0bbf0ffffff29df897de4816dfc3000000031ff4ff755fc297dfcff75d8ff75fcff75 }

condition:
	$a0
}

        