rule Win_Trojan_Agent_32160
{
strings:
	$a0 = { 775565ebf5ca49c2591bff97bb22c1341d7c828a7d55e1697e8fc184f97b154dcec3e7bc31de99946ebc0202d78c275a567a8a5f80f314297a2e8add4a66afc66ddb6ac8a6b1dff1923bb788bb0d890fe38f0935417efcb3e19bf2708b4a908fff8fc13ce19f44717245264f662d6c5e902b84b0a71dd5a328dd7da078c5c71b74e89bfc36deb500090bcaab742ee69283 }

condition:
	$a0
}

        