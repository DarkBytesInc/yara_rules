rule Win_Spyware_Banker_2556
{
strings:
	$a0 = { 7de4b290af1b4a095451afcf877b7abcbfd42c3e7728ce4a0722b075e544db80d77c44f85cc7a1a7d8f6c21e5009551b68b6f7b0debb1f2cb9d8f9583d9e4cbc6ddc11371f57051692d51c77fccb417ea2912a0debdef956fc2be96517ebded777fe4ff4830c4a596ef82a536a503b7f030f69ed5664bb8bbe856d02a6c2b0b4de95ce5fc5ecf525f8ad3c404055ae5816 }

condition:
	$a0
}

        