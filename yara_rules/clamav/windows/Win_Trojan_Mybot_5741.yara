rule Win_Trojan_Mybot_5741
{
strings:
	$a0 = { 189db5b500d428231c0d1db322fcbed4413e4daa33ac2e99e54371a45f93feca092f2b59e5795695eaafbd03c82752ae94588158b9565dddd5a080f8e7199a3e22e42f621f5dff1a5747360e0377be776351303f6872839f7e7dc74625bdc0cda782e5a1872df58d27b456eb97df2b5c776cbe11a24ef3c1fe95f63355a9f9c0 }

condition:
	$a0
}

        